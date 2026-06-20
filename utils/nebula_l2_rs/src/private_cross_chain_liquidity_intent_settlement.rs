use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateCrossChainLiquidityIntentSettlementResult<T> = Result<T, String>;

pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_PROTOCOL_VERSION: &str =
    "nebula-private-cross-chain-liquidity-intent-settlement-v1";
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-liquidity-intent";
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_DEFAULT_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_DEFAULT_AUCTION_BLOCKS: u64 = 8;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_DEFAULT_CHALLENGE_BLOCKS: u64 = 16;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_DOMAINS: usize = 64;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_INTENTS: usize = 4_096;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_SOLVERS: usize = 512;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_ROUTES: usize = 8_192;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_ATTESTATIONS: usize = 8_192;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_RECEIPTS: usize = 8_192;
pub const PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_CHALLENGES: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityDomainKind {
    Monero,
    NebulaL2,
    Ethereum,
    Bitcoin,
    Cosmos,
    Solana,
    Appchain,
}

impl LiquidityDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monero => "monero",
            Self::NebulaL2 => "nebula_l2",
            Self::Ethereum => "ethereum",
            Self::Bitcoin => "bitcoin",
            Self::Cosmos => "cosmos",
            Self::Solana => "solana",
            Self::Appchain => "appchain",
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::NebulaL2 => 500,
            Self::Monero => 1_100,
            Self::Ethereum => 1_500,
            Self::Bitcoin => 1_700,
            Self::Cosmos => 2_000,
            Self::Solana => 2_200,
            Self::Appchain => 2_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Open,
    Quoted,
    Locked,
    Settled,
    Expired,
    Challenged,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Quoted => "quoted",
            Self::Locked => "locked",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Offered,
    Selected,
    Locked,
    Settled,
    Rejected,
    Challenged,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Selected => "selected",
            Self::Locked => "locked",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityDomain {
    pub domain_id: String,
    pub label: String,
    pub kind: LiquidityDomainKind,
    pub finality_blocks: u64,
    pub max_slippage_bps: u64,
    pub low_fee_enabled: bool,
    pub active: bool,
}

impl LiquidityDomain {
    pub fn new(
        label: &str,
        kind: LiquidityDomainKind,
        finality_blocks: u64,
        max_slippage_bps: u64,
        low_fee_enabled: bool,
        active: bool,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        if label.is_empty() {
            return Err("liquidity domain label cannot be empty".to_string());
        }
        if finality_blocks == 0 {
            return Err("liquidity domain finality blocks must be positive".to_string());
        }
        if max_slippage_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("liquidity domain slippage exceeds max bps".to_string());
        }
        let domain_id = private_cross_chain_liquidity_intent_settlement_id(
            "DOMAIN",
            &[label, kind.as_str(), &finality_blocks.to_string()],
        );
        Ok(Self {
            domain_id,
            label: label.to_string(),
            kind,
            finality_blocks,
            max_slippage_bps,
            low_fee_enabled,
            active,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.domain_id.is_empty() || self.label.is_empty() {
            return Err("liquidity domain identifiers cannot be empty".to_string());
        }
        if self.finality_blocks == 0 {
            return Err("liquidity domain finality blocks must be positive".to_string());
        }
        if self.max_slippage_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("liquidity domain slippage exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_domain",
            "domain_id": self.domain_id,
            "label": self.label,
            "domain_kind": self.kind.as_str(),
            "risk_weight_bps": self.kind.risk_weight_bps(),
            "finality_blocks": self.finality_blocks,
            "max_slippage_bps": self.max_slippage_bps,
            "low_fee_enabled": self.low_fee_enabled,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_cross_chain_liquidity_intent_settlement_payload_root(
            "DOMAIN",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquiditySolver {
    pub solver_id: String,
    pub label: String,
    pub pq_identity_commitment: String,
    pub bond_commitment: String,
    pub supported_domain_ids: BTreeSet<String>,
    pub fee_limit_bps: u64,
    pub active: bool,
}

impl LiquiditySolver {
    pub fn new(
        label: &str,
        pq_identity_commitment: &str,
        bond_commitment: &str,
        supported_domain_ids: BTreeSet<String>,
        fee_limit_bps: u64,
        active: bool,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        if label.is_empty() || pq_identity_commitment.is_empty() || bond_commitment.is_empty() {
            return Err("liquidity solver commitments cannot be empty".to_string());
        }
        if supported_domain_ids.is_empty() {
            return Err("liquidity solver must support at least one domain".to_string());
        }
        if fee_limit_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("liquidity solver fee exceeds max bps".to_string());
        }
        let domain_root = private_cross_chain_liquidity_intent_settlement_string_set_root(
            "SOLVER-DOMAINS",
            &supported_domain_ids.iter().cloned().collect::<Vec<_>>(),
        );
        let solver_id = private_cross_chain_liquidity_intent_settlement_id(
            "SOLVER",
            &[label, pq_identity_commitment, &domain_root],
        );
        Ok(Self {
            solver_id,
            label: label.to_string(),
            pq_identity_commitment: pq_identity_commitment.to_string(),
            bond_commitment: bond_commitment.to_string(),
            supported_domain_ids,
            fee_limit_bps,
            active,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.solver_id.is_empty()
            || self.label.is_empty()
            || self.pq_identity_commitment.is_empty()
            || self.bond_commitment.is_empty()
        {
            return Err("liquidity solver identifiers cannot be empty".to_string());
        }
        if self.supported_domain_ids.is_empty() {
            return Err("liquidity solver supported domains cannot be empty".to_string());
        }
        if self.fee_limit_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("liquidity solver fee exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_solver",
            "solver_id": self.solver_id,
            "label": self.label,
            "pq_identity_commitment": self.pq_identity_commitment,
            "bond_commitment": self.bond_commitment,
            "supported_domain_ids": self.supported_domain_ids.iter().cloned().collect::<Vec<_>>(),
            "fee_limit_bps": self.fee_limit_bps,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_cross_chain_liquidity_intent_settlement_payload_root(
            "SOLVER",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityIntent {
    pub intent_id: String,
    pub source_domain_id: String,
    pub target_domain_id: String,
    pub owner_commitment: String,
    pub amount_commitment: String,
    pub asset_commitment: String,
    pub encrypted_route_hint_root: String,
    pub fee_cap_bps: u64,
    pub min_receive_commitment: String,
    pub nullifier_commitment: String,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub status: IntentStatus,
    pub selected_route_id: Option<String>,
}

impl PrivateLiquidityIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_domain_id: &str,
        target_domain_id: &str,
        owner_commitment: &str,
        amount_commitment: &str,
        asset_commitment: &str,
        encrypted_route_hint_root: &str,
        fee_cap_bps: u64,
        min_receive_commitment: &str,
        nullifier_commitment: &str,
        opened_height: u64,
        ttl_blocks: u64,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        if source_domain_id.is_empty()
            || target_domain_id.is_empty()
            || owner_commitment.is_empty()
            || amount_commitment.is_empty()
            || asset_commitment.is_empty()
            || encrypted_route_hint_root.is_empty()
            || min_receive_commitment.is_empty()
            || nullifier_commitment.is_empty()
        {
            return Err("private liquidity intent commitments cannot be empty".to_string());
        }
        if source_domain_id == target_domain_id {
            return Err("private liquidity intent domains must differ".to_string());
        }
        if fee_cap_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("private liquidity intent fee cap exceeds max bps".to_string());
        }
        if ttl_blocks == 0 {
            return Err("private liquidity intent ttl must be positive".to_string());
        }
        let intent_id = private_cross_chain_liquidity_intent_settlement_id(
            "INTENT",
            &[
                source_domain_id,
                target_domain_id,
                owner_commitment,
                amount_commitment,
                nullifier_commitment,
                &opened_height.to_string(),
            ],
        );
        Ok(Self {
            intent_id,
            source_domain_id: source_domain_id.to_string(),
            target_domain_id: target_domain_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            amount_commitment: amount_commitment.to_string(),
            asset_commitment: asset_commitment.to_string(),
            encrypted_route_hint_root: encrypted_route_hint_root.to_string(),
            fee_cap_bps,
            min_receive_commitment: min_receive_commitment.to_string(),
            nullifier_commitment: nullifier_commitment.to_string(),
            opened_height,
            expiry_height: opened_height.saturating_add(ttl_blocks),
            status: IntentStatus::Open,
            selected_route_id: None,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.intent_id.is_empty()
            || self.source_domain_id.is_empty()
            || self.target_domain_id.is_empty()
            || self.owner_commitment.is_empty()
            || self.amount_commitment.is_empty()
            || self.asset_commitment.is_empty()
            || self.encrypted_route_hint_root.is_empty()
            || self.min_receive_commitment.is_empty()
            || self.nullifier_commitment.is_empty()
        {
            return Err("private liquidity intent identifiers cannot be empty".to_string());
        }
        if self.source_domain_id == self.target_domain_id {
            return Err("private liquidity intent domains must differ".to_string());
        }
        if self.expiry_height < self.opened_height {
            return Err("private liquidity intent timing is invalid".to_string());
        }
        if self.fee_cap_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("private liquidity intent fee cap exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn is_live(&self, height: u64) -> bool {
        matches!(
            self.status,
            IntentStatus::Open | IntentStatus::Quoted | IntentStatus::Locked
        ) && height <= self.expiry_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_intent",
            "intent_id": self.intent_id,
            "source_domain_id": self.source_domain_id,
            "target_domain_id": self.target_domain_id,
            "owner_commitment": self.owner_commitment,
            "amount_commitment": self.amount_commitment,
            "asset_commitment": self.asset_commitment,
            "encrypted_route_hint_root": self.encrypted_route_hint_root,
            "fee_cap_bps": self.fee_cap_bps,
            "min_receive_commitment": self.min_receive_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "opened_height": self.opened_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "selected_route_id": self.selected_route_id,
        })
    }

    pub fn root(&self) -> String {
        private_cross_chain_liquidity_intent_settlement_payload_root(
            "INTENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverRouteQuote {
    pub route_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub route_commitment_root: String,
    pub output_amount_commitment: String,
    pub solver_fee_bps: u64,
    pub settlement_deadline_height: u64,
    pub monero_settlement_hint_root: String,
    pub pq_authorization_commitment: String,
    pub status: RouteStatus,
}

impl SolverRouteQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        solver_id: &str,
        route_commitment_root: &str,
        output_amount_commitment: &str,
        solver_fee_bps: u64,
        settlement_deadline_height: u64,
        monero_settlement_hint_root: &str,
        pq_authorization_commitment: &str,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        if intent_id.is_empty()
            || solver_id.is_empty()
            || route_commitment_root.is_empty()
            || output_amount_commitment.is_empty()
            || monero_settlement_hint_root.is_empty()
            || pq_authorization_commitment.is_empty()
        {
            return Err("solver route quote fields cannot be empty".to_string());
        }
        if solver_fee_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("solver route quote fee exceeds max bps".to_string());
        }
        let route_id = private_cross_chain_liquidity_intent_settlement_id(
            "ROUTE",
            &[
                intent_id,
                solver_id,
                route_commitment_root,
                &settlement_deadline_height.to_string(),
            ],
        );
        Ok(Self {
            route_id,
            intent_id: intent_id.to_string(),
            solver_id: solver_id.to_string(),
            route_commitment_root: route_commitment_root.to_string(),
            output_amount_commitment: output_amount_commitment.to_string(),
            solver_fee_bps,
            settlement_deadline_height,
            monero_settlement_hint_root: monero_settlement_hint_root.to_string(),
            pq_authorization_commitment: pq_authorization_commitment.to_string(),
            status: RouteStatus::Offered,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.route_id.is_empty()
            || self.intent_id.is_empty()
            || self.solver_id.is_empty()
            || self.route_commitment_root.is_empty()
            || self.output_amount_commitment.is_empty()
            || self.monero_settlement_hint_root.is_empty()
            || self.pq_authorization_commitment.is_empty()
        {
            return Err("solver route quote identifiers cannot be empty".to_string());
        }
        if self.solver_fee_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("solver route quote fee exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_route_quote",
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "solver_id": self.solver_id,
            "route_commitment_root": self.route_commitment_root,
            "output_amount_commitment": self.output_amount_commitment,
            "solver_fee_bps": self.solver_fee_bps,
            "settlement_deadline_height": self.settlement_deadline_height,
            "monero_settlement_hint_root": self.monero_settlement_hint_root,
            "pq_authorization_commitment": self.pq_authorization_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_chain_liquidity_intent_settlement_payload_root("ROUTE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub attester_commitment: String,
    pub pq_signature_commitment: String,
    pub settlement_witness_root: String,
    pub height: u64,
}

impl SettlementAttestation {
    pub fn new(
        route_id: &str,
        attester_commitment: &str,
        pq_signature_commitment: &str,
        settlement_witness_root: &str,
        height: u64,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        if route_id.is_empty()
            || attester_commitment.is_empty()
            || pq_signature_commitment.is_empty()
            || settlement_witness_root.is_empty()
        {
            return Err("settlement attestation fields cannot be empty".to_string());
        }
        let attestation_id = private_cross_chain_liquidity_intent_settlement_id(
            "ATTESTATION",
            &[
                route_id,
                attester_commitment,
                pq_signature_commitment,
                &height.to_string(),
            ],
        );
        Ok(Self {
            attestation_id,
            route_id: route_id.to_string(),
            attester_commitment: attester_commitment.to_string(),
            pq_signature_commitment: pq_signature_commitment.to_string(),
            settlement_witness_root: settlement_witness_root.to_string(),
            height,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.attestation_id.is_empty()
            || self.route_id.is_empty()
            || self.attester_commitment.is_empty()
            || self.pq_signature_commitment.is_empty()
            || self.settlement_witness_root.is_empty()
        {
            return Err("settlement attestation identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_attestation",
            "attestation_id": self.attestation_id,
            "route_id": self.route_id,
            "attester_commitment": self.attester_commitment,
            "pq_signature_commitment": self.pq_signature_commitment,
            "settlement_witness_root": self.settlement_witness_root,
            "height": self.height,
        })
    }

    pub fn root(&self) -> String {
        private_cross_chain_liquidity_intent_settlement_payload_root(
            "ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub route_id: String,
    pub settlement_tx_commitment: String,
    pub output_note_root: String,
    pub fee_rebate_commitment: String,
    pub height: u64,
}

impl SettlementReceipt {
    pub fn new(
        route_id: &str,
        settlement_tx_commitment: &str,
        output_note_root: &str,
        fee_rebate_commitment: &str,
        height: u64,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        if route_id.is_empty()
            || settlement_tx_commitment.is_empty()
            || output_note_root.is_empty()
            || fee_rebate_commitment.is_empty()
        {
            return Err("settlement receipt fields cannot be empty".to_string());
        }
        let receipt_id = private_cross_chain_liquidity_intent_settlement_id(
            "RECEIPT",
            &[
                route_id,
                settlement_tx_commitment,
                output_note_root,
                &height.to_string(),
            ],
        );
        Ok(Self {
            receipt_id,
            route_id: route_id.to_string(),
            settlement_tx_commitment: settlement_tx_commitment.to_string(),
            output_note_root: output_note_root.to_string(),
            fee_rebate_commitment: fee_rebate_commitment.to_string(),
            height,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.receipt_id.is_empty()
            || self.route_id.is_empty()
            || self.settlement_tx_commitment.is_empty()
            || self.output_note_root.is_empty()
            || self.fee_rebate_commitment.is_empty()
        {
            return Err("settlement receipt identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "receipt_id": self.receipt_id,
            "route_id": self.route_id,
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "output_note_root": self.output_note_root,
            "fee_rebate_commitment": self.fee_rebate_commitment,
            "height": self.height,
        })
    }

    pub fn root(&self) -> String {
        private_cross_chain_liquidity_intent_settlement_payload_root(
            "RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementChallenge {
    pub challenge_id: String,
    pub route_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub status: ChallengeStatus,
}

impl SettlementChallenge {
    pub fn new(
        route_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        opened_height: u64,
        challenge_blocks: u64,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        if route_id.is_empty() || challenger_commitment.is_empty() || evidence_root.is_empty() {
            return Err("settlement challenge fields cannot be empty".to_string());
        }
        if challenge_blocks == 0 {
            return Err("settlement challenge blocks must be positive".to_string());
        }
        let challenge_id = private_cross_chain_liquidity_intent_settlement_id(
            "CHALLENGE",
            &[
                route_id,
                challenger_commitment,
                evidence_root,
                &opened_height.to_string(),
            ],
        );
        Ok(Self {
            challenge_id,
            route_id: route_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_height,
            expiry_height: opened_height.saturating_add(challenge_blocks),
            status: ChallengeStatus::Open,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.challenge_id.is_empty()
            || self.route_id.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("settlement challenge identifiers cannot be empty".to_string());
        }
        if self.expiry_height < self.opened_height {
            return Err("settlement challenge timing is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_challenge",
            "challenge_id": self.challenge_id,
            "route_id": self.route_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_chain_liquidity_intent_settlement_payload_root(
            "CHALLENGE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub intent_ttl_blocks: u64,
    pub auction_blocks: u64,
    pub challenge_blocks: u64,
    pub max_route_fee_bps: u64,
    pub require_pq_authorization: bool,
    pub enable_low_fee_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            intent_ttl_blocks: PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_DEFAULT_TTL_BLOCKS,
            auction_blocks: PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_DEFAULT_AUCTION_BLOCKS,
            challenge_blocks:
                PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_DEFAULT_CHALLENGE_BLOCKS,
            max_route_fee_bps: 90,
            require_pq_authorization: true,
            enable_low_fee_rebates: true,
        }
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.intent_ttl_blocks == 0 || self.auction_blocks == 0 || self.challenge_blocks == 0 {
            return Err("liquidity intent settlement windows must be positive".to_string());
        }
        if self.max_route_fee_bps > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_BPS {
            return Err("liquidity intent settlement route fee exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_liquidity_intent_settlement_config",
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "auction_blocks": self.auction_blocks,
            "challenge_blocks": self.challenge_blocks,
            "max_route_fee_bps": self.max_route_fee_bps,
            "require_pq_authorization": self.require_pq_authorization,
            "enable_low_fee_rebates": self.enable_low_fee_rebates,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub domain_root: String,
    pub solver_root: String,
    pub intent_root: String,
    pub route_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_liquidity_intent_settlement_roots",
            "config_root": self.config_root,
            "domain_root": self.domain_root,
            "solver_root": self.solver_root,
            "intent_root": self.intent_root,
            "route_root": self.route_root,
            "attestation_root": self.attestation_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub domain_count: u64,
    pub solver_count: u64,
    pub active_solver_count: u64,
    pub intent_count: u64,
    pub live_intent_count: u64,
    pub route_count: u64,
    pub selected_route_count: u64,
    pub attestation_count: u64,
    pub receipt_count: u64,
    pub open_challenge_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_liquidity_intent_settlement_counters",
            "domain_count": self.domain_count,
            "solver_count": self.solver_count,
            "active_solver_count": self.active_solver_count,
            "intent_count": self.intent_count,
            "live_intent_count": self.live_intent_count,
            "route_count": self.route_count,
            "selected_route_count": self.selected_route_count,
            "attestation_count": self.attestation_count,
            "receipt_count": self.receipt_count,
            "open_challenge_count": self.open_challenge_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub domains: BTreeMap<String, LiquidityDomain>,
    pub solvers: BTreeMap<String, LiquiditySolver>,
    pub intents: BTreeMap<String, PrivateLiquidityIntent>,
    pub routes: BTreeMap<String, SolverRouteQuote>,
    pub attestations: BTreeMap<String, SettlementAttestation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub challenges: BTreeMap<String, SettlementChallenge>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> PrivateCrossChainLiquidityIntentSettlementResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            domains: BTreeMap::new(),
            solvers: BTreeMap::new(),
            intents: BTreeMap::new(),
            routes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> PrivateCrossChainLiquidityIntentSettlementResult<State> {
        let mut state = Self::new(Config::devnet())?;
        state.height = 2_048;
        let monero = LiquidityDomain::new(
            "monero-mainnet",
            LiquidityDomainKind::Monero,
            20,
            120,
            true,
            true,
        )?;
        let l2 = LiquidityDomain::new(
            "nebula-l2",
            LiquidityDomainKind::NebulaL2,
            1,
            40,
            true,
            true,
        )?;
        let eth = LiquidityDomain::new(
            "ethereum-mainnet",
            LiquidityDomainKind::Ethereum,
            12,
            100,
            true,
            true,
        )?;
        let monero_id = monero.domain_id.clone();
        let l2_id = l2.domain_id.clone();
        let eth_id = eth.domain_id.clone();
        state.insert_domain(monero)?;
        state.insert_domain(l2)?;
        state.insert_domain(eth)?;

        let solver_domains = BTreeSet::from([monero_id.clone(), l2_id.clone(), eth_id.clone()]);
        let solver = LiquiditySolver::new(
            "solver-alpha",
            "pqid:solver-alpha:hybrid",
            "bond:solver-alpha:commitment",
            solver_domains,
            75,
            true,
        )?;
        let solver_id = solver.solver_id.clone();
        state.insert_solver(solver)?;

        let intent = PrivateLiquidityIntent::new(
            &monero_id,
            &l2_id,
            "owner:shielded:commitment:0",
            "amount:sealed:commitment:0",
            "asset:wxmr:commitment",
            &private_cross_chain_liquidity_intent_settlement_payload_root(
                "DEVNET-ROUTE-HINT",
                &json!({"source": monero_id, "target": l2_id}),
            ),
            80,
            "min-receive:commitment:0",
            "nullifier:intent:0",
            state.height,
            state.config.intent_ttl_blocks,
        )?;
        let intent_id = state.submit_intent(intent)?;
        let route_id = state.submit_route_quote(
            &intent_id,
            &solver_id,
            &private_cross_chain_liquidity_intent_settlement_payload_root(
                "DEVNET-ROUTE",
                &json!({"intent_id": intent_id, "solver_id": solver_id}),
            ),
            "output:amount:commitment:0",
            50,
            "monero:settlement:hint:root:0",
            "pq-auth:route:0",
        )?;
        state.select_route(&intent_id, &route_id)?;
        state.record_attestation(
            &route_id,
            "attester:watchtower:0",
            "pq-signature:route:0",
            "settlement-witness:root:0",
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_domain(
        &mut self,
        domain: LiquidityDomain,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.domains.len() >= PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_DOMAINS
            && !self.domains.contains_key(&domain.domain_id)
        {
            return Err("liquidity domain capacity reached".to_string());
        }
        domain.validate()?;
        self.domains.insert(domain.domain_id.clone(), domain);
        Ok(())
    }

    pub fn insert_solver(
        &mut self,
        solver: LiquiditySolver,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if self.solvers.len() >= PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_SOLVERS
            && !self.solvers.contains_key(&solver.solver_id)
        {
            return Err("liquidity solver capacity reached".to_string());
        }
        solver.validate()?;
        for domain_id in &solver.supported_domain_ids {
            if !self.domains.contains_key(domain_id) {
                return Err("liquidity solver references missing domain".to_string());
            }
        }
        self.solvers.insert(solver.solver_id.clone(), solver);
        Ok(())
    }

    pub fn submit_intent(
        &mut self,
        intent: PrivateLiquidityIntent,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<String> {
        if self.intents.len() >= PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_INTENTS {
            return Err("private liquidity intent capacity reached".to_string());
        }
        intent.validate()?;
        if self
            .consumed_nullifiers
            .contains(&intent.nullifier_commitment)
        {
            return Err("private liquidity intent nullifier already consumed".to_string());
        }
        let source = self
            .domains
            .get(&intent.source_domain_id)
            .ok_or_else(|| "private liquidity intent source domain missing".to_string())?;
        let target = self
            .domains
            .get(&intent.target_domain_id)
            .ok_or_else(|| "private liquidity intent target domain missing".to_string())?;
        if !source.active || !target.active {
            return Err("private liquidity intent domain inactive".to_string());
        }
        let intent_id = intent.intent_id.clone();
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_route_quote(
        &mut self,
        intent_id: &str,
        solver_id: &str,
        route_commitment_root: &str,
        output_amount_commitment: &str,
        solver_fee_bps: u64,
        monero_settlement_hint_root: &str,
        pq_authorization_commitment: &str,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<String> {
        if self.routes.len() >= PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_ROUTES {
            return Err("solver route quote capacity reached".to_string());
        }
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| "solver route quote intent missing".to_string())?;
        if !intent.is_live(self.height) {
            return Err("solver route quote intent is not live".to_string());
        }
        if solver_fee_bps > intent.fee_cap_bps || solver_fee_bps > self.config.max_route_fee_bps {
            return Err("solver route quote fee exceeds policy".to_string());
        }
        let solver = self
            .solvers
            .get(solver_id)
            .ok_or_else(|| "solver route quote solver missing".to_string())?;
        if !solver.active {
            return Err("solver route quote solver inactive".to_string());
        }
        if !solver
            .supported_domain_ids
            .contains(&intent.source_domain_id)
            || !solver
                .supported_domain_ids
                .contains(&intent.target_domain_id)
        {
            return Err("solver route quote solver does not support domains".to_string());
        }
        let route = SolverRouteQuote::new(
            intent_id,
            solver_id,
            route_commitment_root,
            output_amount_commitment,
            solver_fee_bps,
            self.height.saturating_add(self.config.intent_ttl_blocks),
            monero_settlement_hint_root,
            pq_authorization_commitment,
        )?;
        let route_id = route.route_id.clone();
        intent.status = IntentStatus::Quoted;
        self.routes.insert(route_id.clone(), route);
        Ok(route_id)
    }

    pub fn select_route(
        &mut self,
        intent_id: &str,
        route_id: &str,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| "route selection intent missing".to_string())?;
        if !intent.is_live(self.height) {
            return Err("route selection intent is not live".to_string());
        }
        let route = self
            .routes
            .get_mut(route_id)
            .ok_or_else(|| "route selection route missing".to_string())?;
        if route.intent_id != intent_id {
            return Err("route selection route intent mismatch".to_string());
        }
        route.status = RouteStatus::Selected;
        intent.status = IntentStatus::Locked;
        intent.selected_route_id = Some(route_id.to_string());
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        route_id: &str,
        attester_commitment: &str,
        pq_signature_commitment: &str,
        settlement_witness_root: &str,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<String> {
        if self.attestations.len()
            >= PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_ATTESTATIONS
        {
            return Err("settlement attestation capacity reached".to_string());
        }
        if !self.routes.contains_key(route_id) {
            return Err("settlement attestation route missing".to_string());
        }
        let attestation = SettlementAttestation::new(
            route_id,
            attester_commitment,
            pq_signature_commitment,
            settlement_witness_root,
            self.height,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn record_receipt(
        &mut self,
        route_id: &str,
        settlement_tx_commitment: &str,
        output_note_root: &str,
        fee_rebate_commitment: &str,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<String> {
        if self.receipts.len() >= PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_RECEIPTS {
            return Err("settlement receipt capacity reached".to_string());
        }
        let intent_id = {
            let route = self
                .routes
                .get_mut(route_id)
                .ok_or_else(|| "settlement receipt route missing".to_string())?;
            route.status = RouteStatus::Settled;
            route.intent_id.clone()
        };
        let intent = self
            .intents
            .get_mut(&intent_id)
            .ok_or_else(|| "settlement receipt intent missing".to_string())?;
        intent.status = IntentStatus::Settled;
        self.consumed_nullifiers
            .insert(intent.nullifier_commitment.clone());
        let receipt = SettlementReceipt::new(
            route_id,
            settlement_tx_commitment,
            output_note_root,
            fee_rebate_commitment,
            self.height,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn open_challenge(
        &mut self,
        route_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<String> {
        if self.challenges.len() >= PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_CHALLENGES {
            return Err("settlement challenge capacity reached".to_string());
        }
        let route = self
            .routes
            .get_mut(route_id)
            .ok_or_else(|| "settlement challenge route missing".to_string())?;
        route.status = RouteStatus::Challenged;
        if let Some(intent) = self.intents.get_mut(&route.intent_id) {
            intent.status = IntentStatus::Challenged;
        }
        let challenge = SettlementChallenge::new(
            route_id,
            challenger_commitment,
            evidence_root,
            self.height,
            self.config.challenge_blocks,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        if height < self.height {
            return Err("liquidity intent settlement height cannot go backwards".to_string());
        }
        self.height = height;
        for intent in self.intents.values_mut() {
            if matches!(
                intent.status,
                IntentStatus::Open | IntentStatus::Quoted | IntentStatus::Locked
            ) && height > intent.expiry_height
            {
                intent.status = IntentStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open && height > challenge.expiry_height {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        self.set_height(height)
    }

    pub fn validate(&self) -> PrivateCrossChainLiquidityIntentSettlementResult<()> {
        self.config.validate()?;
        if self.domains.len() > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_DOMAINS
            || self.solvers.len() > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_SOLVERS
            || self.intents.len() > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_INTENTS
            || self.routes.len() > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_ROUTES
            || self.attestations.len()
                > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_ATTESTATIONS
            || self.receipts.len() > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_RECEIPTS
            || self.challenges.len()
                > PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_MAX_CHALLENGES
        {
            return Err("liquidity intent settlement capacity exceeded".to_string());
        }
        for domain in self.domains.values() {
            domain.validate()?;
        }
        for solver in self.solvers.values() {
            solver.validate()?;
            for domain_id in &solver.supported_domain_ids {
                if !self.domains.contains_key(domain_id) {
                    return Err("liquidity solver references missing domain".to_string());
                }
            }
        }
        for intent in self.intents.values() {
            intent.validate()?;
            if !self.domains.contains_key(&intent.source_domain_id)
                || !self.domains.contains_key(&intent.target_domain_id)
            {
                return Err("liquidity intent references missing domain".to_string());
            }
        }
        for route in self.routes.values() {
            route.validate()?;
            if !self.intents.contains_key(&route.intent_id)
                || !self.solvers.contains_key(&route.solver_id)
            {
                return Err("liquidity route references missing state".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.routes.contains_key(&attestation.route_id) {
                return Err("liquidity attestation references missing route".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.routes.contains_key(&receipt.route_id) {
                return Err("liquidity receipt references missing route".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.routes.contains_key(&challenge.route_id) {
                return Err("liquidity challenge references missing route".to_string());
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_cross_chain_liquidity_intent_settlement_payload_root(
                "CONFIG",
                &self.config.public_record(),
            ),
            domain_root: merkle_root(
                "PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-DOMAINS",
                &self
                    .domains
                    .values()
                    .map(LiquidityDomain::public_record)
                    .collect::<Vec<_>>(),
            ),
            solver_root: merkle_root(
                "PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-SOLVERS",
                &self
                    .solvers
                    .values()
                    .map(LiquiditySolver::public_record)
                    .collect::<Vec<_>>(),
            ),
            intent_root: merkle_root(
                "PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-INTENTS",
                &self
                    .intents
                    .values()
                    .map(PrivateLiquidityIntent::public_record)
                    .collect::<Vec<_>>(),
            ),
            route_root: merkle_root(
                "PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-ROUTES",
                &self
                    .routes
                    .values()
                    .map(SolverRouteQuote::public_record)
                    .collect::<Vec<_>>(),
            ),
            attestation_root: merkle_root(
                "PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-ATTESTATIONS",
                &self
                    .attestations
                    .values()
                    .map(SettlementAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: merkle_root(
                "PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-RECEIPTS",
                &self
                    .receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            challenge_root: merkle_root(
                "PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-CHALLENGES",
                &self
                    .challenges
                    .values()
                    .map(SettlementChallenge::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            domain_count: self.domains.len() as u64,
            solver_count: self.solvers.len() as u64,
            active_solver_count: self.solvers.values().filter(|solver| solver.active).count()
                as u64,
            intent_count: self.intents.len() as u64,
            live_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.is_live(self.height))
                .count() as u64,
            route_count: self.routes.len() as u64,
            selected_route_count: self
                .routes
                .values()
                .filter(|route| matches!(route.status, RouteStatus::Selected | RouteStatus::Locked))
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            receipt_count: self.receipts.len() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count() as u64,
        }
    }

    pub fn live_intent_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| intent.is_live(self.height))
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    pub fn selected_route_ids(&self) -> Vec<String> {
        self.routes
            .values()
            .filter(|route| matches!(route.status, RouteStatus::Selected | RouteStatus::Locked))
            .map(|route| route.route_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Open)
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn domain_pressure_map(&self) -> BTreeMap<String, Value> {
        let mut pressure = BTreeMap::new();
        for domain in self.domains.values() {
            let outbound_count = self
                .intents
                .values()
                .filter(|intent| intent.source_domain_id == domain.domain_id)
                .count() as u64;
            let inbound_count = self
                .intents
                .values()
                .filter(|intent| intent.target_domain_id == domain.domain_id)
                .count() as u64;
            pressure.insert(
                domain.domain_id.clone(),
                json!({
                    "label": domain.label,
                    "domain_kind": domain.kind.as_str(),
                    "outbound_intent_count": outbound_count,
                    "inbound_intent_count": inbound_count,
                    "risk_weight_bps": domain.kind.risk_weight_bps(),
                    "low_fee_enabled": domain.low_fee_enabled,
                }),
            );
        }
        pressure
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_liquidity_intent_settlement_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_HASH_SUITE,
            "pq_auth_suite": PRIVATE_CROSS_CHAIN_LIQUIDITY_INTENT_SETTLEMENT_PQ_AUTH_SUITE,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_intent_ids": self.live_intent_ids(),
            "selected_route_ids": self.selected_route_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
            "domain_pressure_map": self.domain_pressure_map(),
            "consumed_nullifier_root": private_cross_chain_liquidity_intent_settlement_string_set_root(
                "CONSUMED-NULLIFIERS",
                &self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

pub fn root_from_record(record: &Value) -> String {
    private_cross_chain_liquidity_intent_settlement_payload_root("STATE", record)
}

pub fn private_cross_chain_liquidity_intent_settlement_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-SETTLEMENT-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_cross_chain_liquidity_intent_settlement_string_set_root(
    domain: &str,
    values: &[String],
) -> String {
    merkle_root(
        &format!("PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-SETTLEMENT-{domain}"),
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn private_cross_chain_liquidity_intent_settlement_id(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-CHAIN-LIQUIDITY-INTENT-SETTLEMENT-ID-{domain}"),
        &[HashPart::Json(&json!({ "parts": parts }))],
        32,
    )
}

pub fn devnet() -> PrivateCrossChainLiquidityIntentSettlementResult<State> {
    State::devnet()
}
