use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateCrossChainIntentRouterResult<T> = Result<T, String>;

pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_ID: &str =
    "nebula-private-cross-chain-intent-router-v1";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+monero-view-key-sealed-intent-v1";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-solver-route-attestation-v1";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_COMMITMENT_SCHEME: &str =
    "shake256-cross-chain-shielded-intent-commitment-v1";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_SETTLEMENT_PROOF_SCHEME: &str =
    "zk-private-cross-chain-settlement-route-devnet-v1";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_REFUND_PROOF_SCHEME: &str =
    "zk-private-cross-chain-timeout-refund-devnet-v1";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_HEIGHT: u64 = 512;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_REFUND_DELAY_BLOCKS: u64 = 36;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 150_000;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_000;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MAX_SPONSOR_SHARE_BPS: u64 = 8_000;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 400;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_ROUTE_LEGS: usize = 12;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_INTENTS: usize = 131_072;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_QUOTES: usize = 262_144;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_SOLVERS: usize = 16_384;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_SETTLEMENT_LANES: usize = 256;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_PUBLIC_RECORDS: usize = 524_288;
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_XMR_ASSET_ID: &str = "xmr";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DXMR_ASSET_ID: &str = "dxmr";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DUSD_ASSET_ID: &str = "dusd";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_PRIVATE_VM: &str = "nebula-private-vm-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossChainIntentKind {
    MoneroDeposit,
    MoneroWithdrawal,
    PrivateSwap,
    ContractCall,
    VaultDeposit,
    VaultWithdraw,
    DerivativeOpen,
    DerivativeClose,
    Composite,
}

impl CrossChainIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroDeposit => "monero_deposit",
            Self::MoneroWithdrawal => "monero_withdrawal",
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::DerivativeOpen => "derivative_open",
            Self::DerivativeClose => "derivative_close",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterPrivacyMode {
    FullyShielded,
    AmountBucketed,
    RouteFamilyHinted,
    SolverScoped,
    AuditEscrow,
}

impl RouterPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::AmountBucketed => "amount_bucketed",
            Self::RouteFamilyHinted => "route_family_hinted",
            Self::SolverScoped => "solver_scoped",
            Self::AuditEscrow => "audit_escrow",
        }
    }

    pub fn disclosure_bps(self) -> u64 {
        match self {
            Self::FullyShielded => 0,
            Self::AmountBucketed => 150,
            Self::RouteFamilyHinted => 250,
            Self::SolverScoped => 300,
            Self::AuditEscrow => 400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLegKind {
    MoneroEntry,
    MoneroExit,
    PrivateSwap,
    PrivateContractCall,
    TokenTransfer,
    Vault,
    Derivative,
    SettlementEscrow,
    FeeSponsor,
    Refund,
}

impl RouteLegKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroEntry => "monero_entry",
            Self::MoneroExit => "monero_exit",
            Self::PrivateSwap => "private_swap",
            Self::PrivateContractCall => "private_contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::Vault => "vault",
            Self::Derivative => "derivative",
            Self::SettlementEscrow => "settlement_escrow",
            Self::FeeSponsor => "fee_sponsor",
            Self::Refund => "refund",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Quoted,
    Committed,
    Settling,
    Settled,
    Refunding,
    Refunded,
    Expired,
    Cancelled,
    Challenged,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Quoted => "quoted",
            Self::Committed => "committed",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Refunding => "refunding",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Quoted | Self::Committed | Self::Settling | Self::Refunding
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Submitted,
    Shortlisted,
    Selected,
    Superseded,
    Expired,
    Rejected,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Shortlisted => "shortlisted",
            Self::Selected => "selected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Committed,
    Revealed,
    Locked,
    Released,
    Slashed,
    Expired,
}

impl SolverCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLaneStatus {
    Active,
    Congested,
    Degraded,
    Paused,
    Retired,
}

impl SettlementLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Congested => "congested",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutPathStatus {
    Armed,
    Executable,
    Executed,
    Superseded,
    Challenged,
}

impl TimeoutPathStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossChainIntentRouterConfig {
    pub chain_id: String,
    pub protocol_version: u32,
    pub protocol_id: String,
    pub encryption_scheme: String,
    pub commitment_scheme: String,
    pub pq_auth_scheme: String,
    pub settlement_proof_scheme: String,
    pub refund_proof_scheme: String,
    pub intent_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub refund_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_solver_bond_units: u64,
    pub low_fee_rebate_bps: u64,
    pub max_sponsor_share_bps: u64,
    pub max_disclosure_bps: u64,
    pub max_route_legs: usize,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub private_vm_id: String,
}

impl PrivateCrossChainIntentRouterConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            protocol_id: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_ID.to_string(),
            encryption_scheme: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_ENCRYPTION_SCHEME.to_string(),
            commitment_scheme: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_COMMITMENT_SCHEME.to_string(),
            pq_auth_scheme: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PQ_AUTH_SCHEME.to_string(),
            settlement_proof_scheme: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_SETTLEMENT_PROOF_SCHEME
                .to_string(),
            refund_proof_scheme: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_REFUND_PROOF_SCHEME.to_string(),
            intent_ttl_blocks: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_INTENT_TTL_BLOCKS,
            quote_ttl_blocks: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS,
            settlement_ttl_blocks: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            refund_delay_blocks: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_REFUND_DELAY_BLOCKS,
            challenge_window_blocks:
                PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_solver_bond_units: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_SOLVER_BOND_UNITS,
            low_fee_rebate_bps: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_LOW_FEE_REBATE_BPS,
            max_sponsor_share_bps: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MAX_SPONSOR_SHARE_BPS,
            max_disclosure_bps: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MAX_DISCLOSURE_BPS,
            max_route_legs: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_ROUTE_LEGS,
            fee_asset_id: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_FEE_ASSET_ID.to_string(),
            monero_network: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_MONERO_NETWORK.to_string(),
            private_vm_id: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_PRIVATE_VM.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_intent_router_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "encryption_scheme": self.encryption_scheme,
            "commitment_scheme": self.commitment_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "settlement_proof_scheme": self.settlement_proof_scheme,
            "refund_proof_scheme": self.refund_proof_scheme,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "refund_delay_blocks": self.refund_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_solver_bond_units": self.min_solver_bond_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_sponsor_share_bps": self.max_sponsor_share_bps,
            "max_disclosure_bps": self.max_disclosure_bps,
            "max_route_legs": self.max_route_legs,
            "fee_asset_id": self.fee_asset_id,
            "monero_network": self.monero_network,
            "private_vm_id": self.private_vm_id,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<()> {
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_empty("config.protocol_id", &self.protocol_id)?;
        ensure_non_empty("config.encryption_scheme", &self.encryption_scheme)?;
        ensure_non_empty("config.commitment_scheme", &self.commitment_scheme)?;
        ensure_non_empty("config.pq_auth_scheme", &self.pq_auth_scheme)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.monero_network", &self.monero_network)?;
        ensure_non_empty("config.private_vm_id", &self.private_vm_id)?;
        ensure_positive("config.intent_ttl_blocks", self.intent_ttl_blocks)?;
        ensure_positive("config.quote_ttl_blocks", self.quote_ttl_blocks)?;
        ensure_positive("config.settlement_ttl_blocks", self.settlement_ttl_blocks)?;
        ensure_positive("config.refund_delay_blocks", self.refund_delay_blocks)?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        if self.min_pq_security_bits < 256 {
            return Err("config requires at least 256 pq security bits".to_string());
        }
        ensure_positive("config.min_solver_bond_units", self.min_solver_bond_units)?;
        ensure_bps("config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        ensure_bps("config.max_sponsor_share_bps", self.max_sponsor_share_bps)?;
        ensure_bps("config.max_disclosure_bps", self.max_disclosure_bps)?;
        if self.max_route_legs == 0 {
            return Err("config.max_route_legs must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroStealthEndpoint {
    pub endpoint_id: String,
    pub network: String,
    pub direction: String,
    pub spend_key_commitment: String,
    pub view_key_commitment: String,
    pub one_time_address_root: String,
    pub payment_id_commitment: String,
    pub subaddress_index_commitment: String,
    pub amount_bucket_id: String,
    pub ring_decoy_set_root: String,
    pub unlock_height: u64,
}

impl MoneroStealthEndpoint {
    pub fn new(
        network: &str,
        direction: &str,
        owner_hint: &str,
        amount_bucket_id: &str,
        unlock_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("endpoint.network", network)?;
        ensure_non_empty("endpoint.direction", direction)?;
        ensure_non_empty("endpoint.owner_hint", owner_hint)?;
        ensure_non_empty("endpoint.amount_bucket_id", amount_bucket_id)?;
        let spend_key_commitment = string_root("MONERO-SPEND-KEY", owner_hint);
        let view_key_commitment = string_root("MONERO-VIEW-KEY", owner_hint);
        let one_time_address_root = payload_root(
            "MONERO-ONE-TIME-ADDRESS",
            &json!({ "owner_hint": owner_hint }),
        );
        let payment_id_commitment = string_root("MONERO-PAYMENT-ID", owner_hint);
        let subaddress_index_commitment = string_root("MONERO-SUBADDRESS-INDEX", owner_hint);
        let ring_decoy_set_root = payload_root(
            "MONERO-RING-DECOY-SET",
            &json!({ "owner_hint": owner_hint, "bucket": amount_bucket_id }),
        );
        let endpoint_id = id_root(
            "MONERO-STEALTH-ENDPOINT-ID",
            &[
                HashPart::Str(network),
                HashPart::Str(direction),
                HashPart::Str(&one_time_address_root),
                HashPart::Int(unlock_height as i128),
            ],
        );
        Ok(Self {
            endpoint_id,
            network: network.to_string(),
            direction: direction.to_string(),
            spend_key_commitment,
            view_key_commitment,
            one_time_address_root,
            payment_id_commitment,
            subaddress_index_commitment,
            amount_bucket_id: amount_bucket_id.to_string(),
            ring_decoy_set_root,
            unlock_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_stealth_endpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "network": self.network,
            "direction": self.direction,
            "spend_key_commitment": self.spend_key_commitment,
            "view_key_commitment": self.view_key_commitment,
            "one_time_address_root": self.one_time_address_root,
            "payment_id_commitment": self.payment_id_commitment,
            "subaddress_index_commitment": self.subaddress_index_commitment,
            "amount_bucket_id": self.amount_bucket_id,
            "ring_decoy_set_root": self.ring_decoy_set_root,
            "unlock_height": self.unlock_height,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("endpoint.endpoint_id", &self.endpoint_id)?;
        ensure_non_empty("endpoint.network", &self.network)?;
        ensure_non_empty("endpoint.direction", &self.direction)?;
        ensure_root("endpoint.spend_key_commitment", &self.spend_key_commitment)?;
        ensure_root("endpoint.view_key_commitment", &self.view_key_commitment)?;
        ensure_root(
            "endpoint.one_time_address_root",
            &self.one_time_address_root,
        )?;
        ensure_root(
            "endpoint.payment_id_commitment",
            &self.payment_id_commitment,
        )?;
        ensure_root(
            "endpoint.subaddress_index_commitment",
            &self.subaddress_index_commitment,
        )?;
        ensure_non_empty("endpoint.amount_bucket_id", &self.amount_bucket_id)?;
        ensure_root("endpoint.ring_decoy_set_root", &self.ring_decoy_set_root)?;
        Ok(self.endpoint_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCrossChainIntent {
    pub intent_id: String,
    pub wallet_commitment: String,
    pub kind: CrossChainIntentKind,
    pub privacy_mode: RouterPrivacyMode,
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub input_asset_commitment: String,
    pub output_asset_commitment: String,
    pub input_amount_commitment: String,
    pub min_output_amount_commitment: String,
    pub amount_bucket_id: String,
    pub encrypted_payload_root: String,
    pub route_hint_root: String,
    pub monero_entry_endpoint_id: String,
    pub monero_exit_endpoint_id: String,
    pub refund_commitment_root: String,
    pub max_fee_units: u64,
    pub max_disclosure_bps: u64,
    pub min_privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: IntentStatus,
}

impl EncryptedCrossChainIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_label: &str,
        kind: CrossChainIntentKind,
        privacy_mode: RouterPrivacyMode,
        source_chain_id: &str,
        destination_chain_id: &str,
        input_asset_id: &str,
        output_asset_id: &str,
        input_amount_units: u64,
        min_output_units: u64,
        amount_bucket_id: &str,
        encrypted_payload: &Value,
        route_hint: &Value,
        monero_entry_endpoint_id: &str,
        monero_exit_endpoint_id: &str,
        refund_label: &str,
        max_fee_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("intent.wallet_label", wallet_label)?;
        ensure_non_empty("intent.source_chain_id", source_chain_id)?;
        ensure_non_empty("intent.destination_chain_id", destination_chain_id)?;
        ensure_non_empty("intent.input_asset_id", input_asset_id)?;
        ensure_non_empty("intent.output_asset_id", output_asset_id)?;
        ensure_positive("intent.input_amount_units", input_amount_units)?;
        ensure_positive("intent.min_output_units", min_output_units)?;
        ensure_non_empty("intent.amount_bucket_id", amount_bucket_id)?;
        ensure_non_empty("intent.monero_entry_endpoint_id", monero_entry_endpoint_id)?;
        ensure_non_empty("intent.monero_exit_endpoint_id", monero_exit_endpoint_id)?;
        ensure_positive("intent.max_fee_units", max_fee_units)?;
        ensure_height_order("intent.submitted", submitted_at_height, expires_at_height)?;
        let wallet_commitment = string_root("INTENT-WALLET", wallet_label);
        let input_asset_commitment = string_root("INTENT-ASSET-IN", input_asset_id);
        let output_asset_commitment = string_root("INTENT-ASSET-OUT", output_asset_id);
        let input_amount_commitment =
            amount_root("INTENT-AMOUNT-IN", input_amount_units, wallet_label);
        let min_output_amount_commitment =
            amount_root("INTENT-MIN-OUT", min_output_units, wallet_label);
        let encrypted_payload_root = payload_root("INTENT-ENCRYPTED-PAYLOAD", encrypted_payload);
        let route_hint_root = payload_root("INTENT-ROUTE-HINT", route_hint);
        let refund_commitment_root = string_root("INTENT-REFUND", refund_label);
        let intent_id = id_root(
            "CROSS-CHAIN-INTENT-ID",
            &[
                HashPart::Str(&wallet_commitment),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&encrypted_payload_root),
                HashPart::Int(submitted_at_height as i128),
                HashPart::Int(nonce as i128),
            ],
        );
        Ok(Self {
            intent_id,
            wallet_commitment,
            kind,
            privacy_mode,
            source_chain_id: source_chain_id.to_string(),
            destination_chain_id: destination_chain_id.to_string(),
            input_asset_commitment,
            output_asset_commitment,
            input_amount_commitment,
            min_output_amount_commitment,
            amount_bucket_id: amount_bucket_id.to_string(),
            encrypted_payload_root,
            route_hint_root,
            monero_entry_endpoint_id: monero_entry_endpoint_id.to_string(),
            monero_exit_endpoint_id: monero_exit_endpoint_id.to_string(),
            refund_commitment_root,
            max_fee_units,
            max_disclosure_bps: privacy_mode.disclosure_bps(),
            min_privacy_set_size: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: IntentStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_cross_chain_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "wallet_commitment": self.wallet_commitment,
            "intent_kind": self.kind.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "source_chain_id": self.source_chain_id,
            "destination_chain_id": self.destination_chain_id,
            "input_asset_commitment": self.input_asset_commitment,
            "output_asset_commitment": self.output_asset_commitment,
            "input_amount_commitment": self.input_amount_commitment,
            "min_output_amount_commitment": self.min_output_amount_commitment,
            "amount_bucket_id": self.amount_bucket_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "route_hint_root": self.route_hint_root,
            "monero_entry_endpoint_id": self.monero_entry_endpoint_id,
            "monero_exit_endpoint_id": self.monero_exit_endpoint_id,
            "refund_commitment_root": self.refund_commitment_root,
            "max_fee_units": self.max_fee_units,
            "max_disclosure_bps": self.max_disclosure_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("intent.intent_id", &self.intent_id)?;
        ensure_root("intent.wallet_commitment", &self.wallet_commitment)?;
        ensure_non_empty("intent.source_chain_id", &self.source_chain_id)?;
        ensure_non_empty("intent.destination_chain_id", &self.destination_chain_id)?;
        ensure_root(
            "intent.input_asset_commitment",
            &self.input_asset_commitment,
        )?;
        ensure_root(
            "intent.output_asset_commitment",
            &self.output_asset_commitment,
        )?;
        ensure_root(
            "intent.input_amount_commitment",
            &self.input_amount_commitment,
        )?;
        ensure_root(
            "intent.min_output_amount_commitment",
            &self.min_output_amount_commitment,
        )?;
        ensure_non_empty("intent.amount_bucket_id", &self.amount_bucket_id)?;
        ensure_root(
            "intent.encrypted_payload_root",
            &self.encrypted_payload_root,
        )?;
        ensure_root("intent.route_hint_root", &self.route_hint_root)?;
        ensure_non_empty(
            "intent.monero_entry_endpoint_id",
            &self.monero_entry_endpoint_id,
        )?;
        ensure_non_empty(
            "intent.monero_exit_endpoint_id",
            &self.monero_exit_endpoint_id,
        )?;
        ensure_root(
            "intent.refund_commitment_root",
            &self.refund_commitment_root,
        )?;
        ensure_positive("intent.max_fee_units", self.max_fee_units)?;
        ensure_bps("intent.max_disclosure_bps", self.max_disclosure_bps)?;
        ensure_positive("intent.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_height_order(
            "intent.submitted",
            self.submitted_at_height,
            self.expires_at_height,
        )?;
        Ok(self.intent_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRouteLeg {
    pub leg_id: String,
    pub leg_index: u64,
    pub leg_kind: RouteLegKind,
    pub source_domain: String,
    pub destination_domain: String,
    pub adapter_id: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub amount_out_commitment: String,
    pub fee_units: u64,
    pub privacy_bucket_id: String,
    pub call_data_root: String,
    pub guard_root: String,
}

impl PrivateRouteLeg {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        leg_index: u64,
        leg_kind: RouteLegKind,
        source_domain: &str,
        destination_domain: &str,
        adapter_id: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in_units: u64,
        amount_out_units: u64,
        fee_units: u64,
        privacy_bucket_id: &str,
        call_data: &Value,
        guard: &Value,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("leg.source_domain", source_domain)?;
        ensure_non_empty("leg.destination_domain", destination_domain)?;
        ensure_non_empty("leg.adapter_id", adapter_id)?;
        ensure_non_empty("leg.asset_in_id", asset_in_id)?;
        ensure_non_empty("leg.asset_out_id", asset_out_id)?;
        ensure_non_empty("leg.privacy_bucket_id", privacy_bucket_id)?;
        let asset_in_commitment = string_root("LEG-ASSET-IN", asset_in_id);
        let asset_out_commitment = string_root("LEG-ASSET-OUT", asset_out_id);
        let amount_in_commitment = amount_root("LEG-AMOUNT-IN", amount_in_units, adapter_id);
        let amount_out_commitment = amount_root("LEG-AMOUNT-OUT", amount_out_units, adapter_id);
        let call_data_root = payload_root("LEG-CALL-DATA", call_data);
        let guard_root = payload_root("LEG-GUARD", guard);
        let leg_id = id_root(
            "PRIVATE-ROUTE-LEG-ID",
            &[
                HashPart::Int(leg_index as i128),
                HashPart::Str(leg_kind.as_str()),
                HashPart::Str(source_domain),
                HashPart::Str(destination_domain),
                HashPart::Str(&call_data_root),
            ],
        );
        Ok(Self {
            leg_id,
            leg_index,
            leg_kind,
            source_domain: source_domain.to_string(),
            destination_domain: destination_domain.to_string(),
            adapter_id: adapter_id.to_string(),
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            amount_out_commitment,
            fee_units,
            privacy_bucket_id: privacy_bucket_id.to_string(),
            call_data_root,
            guard_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_route_leg",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "leg_id": self.leg_id,
            "leg_index": self.leg_index,
            "leg_kind": self.leg_kind.as_str(),
            "source_domain": self.source_domain,
            "destination_domain": self.destination_domain,
            "adapter_id": self.adapter_id,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_commitment": self.amount_out_commitment,
            "fee_units": self.fee_units,
            "privacy_bucket_id": self.privacy_bucket_id,
            "call_data_root": self.call_data_root,
            "guard_root": self.guard_root,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("leg.leg_id", &self.leg_id)?;
        ensure_non_empty("leg.source_domain", &self.source_domain)?;
        ensure_non_empty("leg.destination_domain", &self.destination_domain)?;
        ensure_non_empty("leg.adapter_id", &self.adapter_id)?;
        ensure_root("leg.asset_in_commitment", &self.asset_in_commitment)?;
        ensure_root("leg.asset_out_commitment", &self.asset_out_commitment)?;
        ensure_root("leg.amount_in_commitment", &self.amount_in_commitment)?;
        ensure_root("leg.amount_out_commitment", &self.amount_out_commitment)?;
        ensure_non_empty("leg.privacy_bucket_id", &self.privacy_bucket_id)?;
        ensure_root("leg.call_data_root", &self.call_data_root)?;
        ensure_root("leg.guard_root", &self.guard_root)?;
        Ok(self.leg_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteQuote {
    pub quote_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub attestation_id: String,
    pub lane_id: String,
    pub route_legs: Vec<PrivateRouteLeg>,
    pub route_root: String,
    pub guaranteed_output_commitment: String,
    pub quoted_fee_units: u64,
    pub sponsor_units: u64,
    pub solver_fee_units: u64,
    pub latency_blocks: u64,
    pub privacy_score_bps: u64,
    pub price_score_bps: u64,
    pub quote_secret_commitment: String,
    pub quote_signature_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuoteStatus,
}

impl RouteQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        solver_id: &str,
        attestation_id: &str,
        lane_id: &str,
        route_legs: Vec<PrivateRouteLeg>,
        guaranteed_output_units: u64,
        quoted_fee_units: u64,
        sponsor_units: u64,
        solver_fee_units: u64,
        latency_blocks: u64,
        privacy_score_bps: u64,
        price_score_bps: u64,
        quote_secret: &str,
        signature: &Value,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("quote.intent_id", intent_id)?;
        ensure_non_empty("quote.solver_id", solver_id)?;
        ensure_non_empty("quote.attestation_id", attestation_id)?;
        ensure_non_empty("quote.lane_id", lane_id)?;
        ensure_positive("quote.guaranteed_output_units", guaranteed_output_units)?;
        ensure_positive("quote.latency_blocks", latency_blocks)?;
        ensure_bps("quote.privacy_score_bps", privacy_score_bps)?;
        ensure_bps("quote.price_score_bps", price_score_bps)?;
        ensure_height_order("quote.created", created_at_height, expires_at_height)?;
        if route_legs.is_empty() {
            return Err("quote requires at least one route leg".to_string());
        }
        if route_legs.len() > PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_ROUTE_LEGS {
            return Err("quote has too many route legs".to_string());
        }
        let route_root = value_merkle_root(
            "QUOTE-ROUTE-LEGS",
            route_legs
                .iter()
                .map(PrivateRouteLeg::public_record)
                .collect::<Vec<_>>(),
        );
        let guaranteed_output_commitment =
            amount_root("QUOTE-GUARANTEED-OUT", guaranteed_output_units, solver_id);
        let quote_secret_commitment = string_root("QUOTE-SECRET", quote_secret);
        let quote_signature_root = payload_root("QUOTE-SIGNATURE", signature);
        let quote_id = id_root(
            "ROUTE-QUOTE-ID",
            &[
                HashPart::Str(intent_id),
                HashPart::Str(solver_id),
                HashPart::Str(&route_root),
                HashPart::Int(quoted_fee_units as i128),
                HashPart::Int(created_at_height as i128),
            ],
        );
        Ok(Self {
            quote_id,
            intent_id: intent_id.to_string(),
            solver_id: solver_id.to_string(),
            attestation_id: attestation_id.to_string(),
            lane_id: lane_id.to_string(),
            route_legs,
            route_root,
            guaranteed_output_commitment,
            quoted_fee_units,
            sponsor_units,
            solver_fee_units,
            latency_blocks,
            privacy_score_bps,
            price_score_bps,
            quote_secret_commitment,
            quote_signature_root,
            created_at_height,
            expires_at_height,
            status: QuoteStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "route_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "intent_id": self.intent_id,
            "solver_id": self.solver_id,
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "route_root": self.route_root,
            "route_legs": self.route_legs.iter().map(PrivateRouteLeg::public_record).collect::<Vec<_>>(),
            "guaranteed_output_commitment": self.guaranteed_output_commitment,
            "quoted_fee_units": self.quoted_fee_units,
            "sponsor_units": self.sponsor_units,
            "solver_fee_units": self.solver_fee_units,
            "latency_blocks": self.latency_blocks,
            "privacy_score_bps": self.privacy_score_bps,
            "price_score_bps": self.price_score_bps,
            "quote_secret_commitment": self.quote_secret_commitment,
            "quote_signature_root": self.quote_signature_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("quote.quote_id", &self.quote_id)?;
        ensure_non_empty("quote.intent_id", &self.intent_id)?;
        ensure_non_empty("quote.solver_id", &self.solver_id)?;
        ensure_non_empty("quote.attestation_id", &self.attestation_id)?;
        ensure_non_empty("quote.lane_id", &self.lane_id)?;
        ensure_root("quote.route_root", &self.route_root)?;
        ensure_root(
            "quote.guaranteed_output_commitment",
            &self.guaranteed_output_commitment,
        )?;
        ensure_positive("quote.latency_blocks", self.latency_blocks)?;
        ensure_bps("quote.privacy_score_bps", self.privacy_score_bps)?;
        ensure_bps("quote.price_score_bps", self.price_score_bps)?;
        ensure_root(
            "quote.quote_secret_commitment",
            &self.quote_secret_commitment,
        )?;
        ensure_root("quote.quote_signature_root", &self.quote_signature_root)?;
        ensure_height_order(
            "quote.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        if self.route_legs.is_empty() {
            return Err("quote route leg set cannot be empty".to_string());
        }
        for leg in &self.route_legs {
            leg.validate()?;
        }
        Ok(self.quote_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverProfile {
    pub solver_id: String,
    pub operator_commitment: String,
    pub bond_asset_id: String,
    pub bond_units: u64,
    pub supported_lane_root: String,
    pub supported_asset_root: String,
    pub private_endpoint_root: String,
    pub max_parallel_intents: u64,
    pub median_latency_ms: u64,
    pub reliability_bps: u64,
    pub status: String,
}

impl SolverProfile {
    pub fn new(
        solver_label: &str,
        operator_label: &str,
        bond_asset_id: &str,
        bond_units: u64,
        supported_lanes: &[String],
        supported_assets: &[String],
        private_endpoint: &str,
        max_parallel_intents: u64,
        median_latency_ms: u64,
        reliability_bps: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("solver.solver_label", solver_label)?;
        ensure_non_empty("solver.operator_label", operator_label)?;
        ensure_non_empty("solver.bond_asset_id", bond_asset_id)?;
        ensure_positive("solver.bond_units", bond_units)?;
        ensure_positive("solver.max_parallel_intents", max_parallel_intents)?;
        ensure_positive("solver.median_latency_ms", median_latency_ms)?;
        ensure_bps("solver.reliability_bps", reliability_bps)?;
        let operator_commitment = string_root("SOLVER-OPERATOR", operator_label);
        let supported_lane_root = string_set_root("SOLVER-LANES", supported_lanes);
        let supported_asset_root = string_set_root("SOLVER-ASSETS", supported_assets);
        let private_endpoint_root = string_root("SOLVER-PRIVATE-ENDPOINT", private_endpoint);
        let solver_id = id_root(
            "SOLVER-PROFILE-ID",
            &[
                HashPart::Str(solver_label),
                HashPart::Str(&operator_commitment),
                HashPart::Str(&supported_lane_root),
            ],
        );
        Ok(Self {
            solver_id,
            operator_commitment,
            bond_asset_id: bond_asset_id.to_string(),
            bond_units,
            supported_lane_root,
            supported_asset_root,
            private_endpoint_root,
            max_parallel_intents,
            median_latency_ms,
            reliability_bps,
            status: "active".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "solver_id": self.solver_id,
            "operator_commitment": self.operator_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bond_units": self.bond_units,
            "supported_lane_root": self.supported_lane_root,
            "supported_asset_root": self.supported_asset_root,
            "private_endpoint_root": self.private_endpoint_root,
            "max_parallel_intents": self.max_parallel_intents,
            "median_latency_ms": self.median_latency_ms,
            "reliability_bps": self.reliability_bps,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("solver.solver_id", &self.solver_id)?;
        ensure_root("solver.operator_commitment", &self.operator_commitment)?;
        ensure_non_empty("solver.bond_asset_id", &self.bond_asset_id)?;
        ensure_positive("solver.bond_units", self.bond_units)?;
        ensure_root("solver.supported_lane_root", &self.supported_lane_root)?;
        ensure_root("solver.supported_asset_root", &self.supported_asset_root)?;
        ensure_root("solver.private_endpoint_root", &self.private_endpoint_root)?;
        ensure_positive("solver.max_parallel_intents", self.max_parallel_intents)?;
        ensure_positive("solver.median_latency_ms", self.median_latency_ms)?;
        ensure_bps("solver.reliability_bps", self.reliability_bps)?;
        ensure_non_empty("solver.status", &self.status)?;
        Ok(self.solver_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSolverAttestation {
    pub attestation_id: String,
    pub solver_id: String,
    pub kem_public_key_root: String,
    pub signature_root: String,
    pub capability_root: String,
    pub hardware_root: String,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqSolverAttestation {
    pub fn new(
        solver_id: &str,
        kem_public_key: &str,
        signature: &Value,
        capabilities: &[String],
        hardware: &Value,
        pq_security_bits: u16,
        attested_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("attestation.solver_id", solver_id)?;
        ensure_non_empty("attestation.kem_public_key", kem_public_key)?;
        if pq_security_bits < PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("attestation pq security bits below router floor".to_string());
        }
        ensure_height_order(
            "attestation.attested",
            attested_at_height,
            expires_at_height,
        )?;
        let kem_public_key_root = string_root("PQ-KEM-PUBLIC-KEY", kem_public_key);
        let signature_root = payload_root("PQ-SIGNATURE", signature);
        let capability_root = string_set_root("PQ-CAPABILITIES", capabilities);
        let hardware_root = payload_root("PQ-HARDWARE", hardware);
        let attestation_id = id_root(
            "PQ-SOLVER-ATTESTATION-ID",
            &[
                HashPart::Str(solver_id),
                HashPart::Str(&kem_public_key_root),
                HashPart::Str(&signature_root),
                HashPart::Int(attested_at_height as i128),
            ],
        );
        Ok(Self {
            attestation_id,
            solver_id: solver_id.to_string(),
            kem_public_key_root,
            signature_root,
            capability_root,
            hardware_root,
            pq_security_bits,
            attested_at_height,
            expires_at_height,
            status: "verified".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_solver_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "solver_id": self.solver_id,
            "kem_public_key_root": self.kem_public_key_root,
            "signature_root": self.signature_root,
            "capability_root": self.capability_root,
            "hardware_root": self.hardware_root,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("attestation.attestation_id", &self.attestation_id)?;
        ensure_non_empty("attestation.solver_id", &self.solver_id)?;
        ensure_root("attestation.kem_public_key_root", &self.kem_public_key_root)?;
        ensure_root("attestation.signature_root", &self.signature_root)?;
        ensure_root("attestation.capability_root", &self.capability_root)?;
        ensure_root("attestation.hardware_root", &self.hardware_root)?;
        if self.pq_security_bits < PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("attestation pq security bits below router floor".to_string());
        }
        ensure_height_order(
            "attestation.attested",
            self.attested_at_height,
            self.expires_at_height,
        )?;
        ensure_non_empty("attestation.status", &self.status)?;
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub solver_id: String,
    pub quote_id: String,
    pub intent_id: String,
    pub escrow_ref_id: String,
    pub bond_lock_units: u64,
    pub commitment_root: String,
    pub reveal_root: String,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub status: SolverCommitmentStatus,
}

impl SolverCommitment {
    pub fn new(
        solver_id: &str,
        quote_id: &str,
        intent_id: &str,
        escrow_ref_id: &str,
        bond_lock_units: u64,
        secret: &Value,
        committed_at_height: u64,
        reveal_deadline_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("commitment.solver_id", solver_id)?;
        ensure_non_empty("commitment.quote_id", quote_id)?;
        ensure_non_empty("commitment.intent_id", intent_id)?;
        ensure_non_empty("commitment.escrow_ref_id", escrow_ref_id)?;
        ensure_positive("commitment.bond_lock_units", bond_lock_units)?;
        ensure_height_order(
            "commitment.committed",
            committed_at_height,
            reveal_deadline_height,
        )?;
        let commitment_root = payload_root("SOLVER-COMMITMENT", secret);
        let reveal_root = payload_root(
            "SOLVER-COMMITMENT-REVEAL",
            &json!({ "quote_id": quote_id, "escrow_ref_id": escrow_ref_id }),
        );
        let commitment_id = id_root(
            "SOLVER-COMMITMENT-ID",
            &[
                HashPart::Str(solver_id),
                HashPart::Str(quote_id),
                HashPart::Str(&commitment_root),
                HashPart::Int(committed_at_height as i128),
            ],
        );
        Ok(Self {
            commitment_id,
            solver_id: solver_id.to_string(),
            quote_id: quote_id.to_string(),
            intent_id: intent_id.to_string(),
            escrow_ref_id: escrow_ref_id.to_string(),
            bond_lock_units,
            commitment_root,
            reveal_root,
            committed_at_height,
            reveal_deadline_height,
            status: SolverCommitmentStatus::Committed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "solver_id": self.solver_id,
            "quote_id": self.quote_id,
            "intent_id": self.intent_id,
            "escrow_ref_id": self.escrow_ref_id,
            "bond_lock_units": self.bond_lock_units,
            "commitment_root": self.commitment_root,
            "reveal_root": self.reveal_root,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("commitment.commitment_id", &self.commitment_id)?;
        ensure_non_empty("commitment.solver_id", &self.solver_id)?;
        ensure_non_empty("commitment.quote_id", &self.quote_id)?;
        ensure_non_empty("commitment.intent_id", &self.intent_id)?;
        ensure_non_empty("commitment.escrow_ref_id", &self.escrow_ref_id)?;
        ensure_positive("commitment.bond_lock_units", self.bond_lock_units)?;
        ensure_root("commitment.commitment_root", &self.commitment_root)?;
        ensure_root("commitment.reveal_root", &self.reveal_root)?;
        ensure_height_order(
            "commitment.committed",
            self.committed_at_height,
            self.reveal_deadline_height,
        )?;
        Ok(self.commitment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementEscrowRef {
    pub escrow_ref_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub escrow_contract_commitment: String,
    pub deposit_nullifier_root: String,
    pub release_note_root: String,
    pub refund_note_root: String,
    pub locked_fee_units: u64,
    pub opened_at_height: u64,
    pub release_after_height: u64,
}

impl SettlementEscrowRef {
    pub fn new(
        intent_id: &str,
        quote_id: &str,
        escrow_contract: &str,
        deposit: &Value,
        release: &Value,
        refund: &Value,
        locked_fee_units: u64,
        opened_at_height: u64,
        release_after_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("escrow.intent_id", intent_id)?;
        ensure_non_empty("escrow.quote_id", quote_id)?;
        ensure_non_empty("escrow.escrow_contract", escrow_contract)?;
        ensure_height_order("escrow.opened", opened_at_height, release_after_height)?;
        let escrow_contract_commitment = string_root("ESCROW-CONTRACT", escrow_contract);
        let deposit_nullifier_root = payload_root("ESCROW-DEPOSIT", deposit);
        let release_note_root = payload_root("ESCROW-RELEASE", release);
        let refund_note_root = payload_root("ESCROW-REFUND", refund);
        let escrow_ref_id = id_root(
            "SETTLEMENT-ESCROW-REF-ID",
            &[
                HashPart::Str(intent_id),
                HashPart::Str(quote_id),
                HashPart::Str(&deposit_nullifier_root),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Ok(Self {
            escrow_ref_id,
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            escrow_contract_commitment,
            deposit_nullifier_root,
            release_note_root,
            refund_note_root,
            locked_fee_units,
            opened_at_height,
            release_after_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_escrow_ref",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "escrow_ref_id": self.escrow_ref_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "escrow_contract_commitment": self.escrow_contract_commitment,
            "deposit_nullifier_root": self.deposit_nullifier_root,
            "release_note_root": self.release_note_root,
            "refund_note_root": self.refund_note_root,
            "locked_fee_units": self.locked_fee_units,
            "opened_at_height": self.opened_at_height,
            "release_after_height": self.release_after_height,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("escrow.escrow_ref_id", &self.escrow_ref_id)?;
        ensure_non_empty("escrow.intent_id", &self.intent_id)?;
        ensure_non_empty("escrow.quote_id", &self.quote_id)?;
        ensure_root(
            "escrow.escrow_contract_commitment",
            &self.escrow_contract_commitment,
        )?;
        ensure_root(
            "escrow.deposit_nullifier_root",
            &self.deposit_nullifier_root,
        )?;
        ensure_root("escrow.release_note_root", &self.release_note_root)?;
        ensure_root("escrow.refund_note_root", &self.refund_note_root)?;
        ensure_height_order(
            "escrow.opened",
            self.opened_at_height,
            self.release_after_height,
        )?;
        Ok(self.escrow_ref_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub rebate_bps: u64,
    pub policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSponsorship {
    pub fn new(
        sponsor_label: &str,
        lane_id: &str,
        asset_id: &str,
        budget_units: u64,
        rebate_bps: u64,
        policy: &Value,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("sponsorship.sponsor_label", sponsor_label)?;
        ensure_non_empty("sponsorship.lane_id", lane_id)?;
        ensure_non_empty("sponsorship.asset_id", asset_id)?;
        ensure_positive("sponsorship.budget_units", budget_units)?;
        ensure_bps("sponsorship.rebate_bps", rebate_bps)?;
        ensure_height_order("sponsorship.created", created_at_height, expires_at_height)?;
        let sponsor_commitment = string_root("SPONSOR-COMMITMENT", sponsor_label);
        let policy_root = payload_root("SPONSOR-POLICY", policy);
        let sponsorship_id = id_root(
            "LOW-FEE-SPONSORSHIP-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(lane_id),
                HashPart::Str(&policy_root),
                HashPart::Int(created_at_height as i128),
            ],
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            rebate_bps,
            policy_root,
            created_at_height,
            expires_at_height,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "rebate_bps": self.rebate_bps,
            "policy_root": self.policy_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("sponsorship.sponsorship_id", &self.sponsorship_id)?;
        ensure_root("sponsorship.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("sponsorship.lane_id", &self.lane_id)?;
        ensure_non_empty("sponsorship.asset_id", &self.asset_id)?;
        ensure_positive("sponsorship.budget_units", self.budget_units)?;
        ensure_bps("sponsorship.rebate_bps", self.rebate_bps)?;
        ensure_root("sponsorship.policy_root", &self.policy_root)?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("sponsorship reserved plus spent exceeds budget".to_string());
        }
        ensure_height_order(
            "sponsorship.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutRefundPath {
    pub timeout_path_id: String,
    pub intent_id: String,
    pub escrow_ref_id: String,
    pub refund_endpoint_id: String,
    pub refund_nullifier_root: String,
    pub proof_root: String,
    pub armed_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub status: TimeoutPathStatus,
}

impl TimeoutRefundPath {
    pub fn new(
        intent_id: &str,
        escrow_ref_id: &str,
        refund_endpoint_id: &str,
        proof: &Value,
        armed_at_height: u64,
        executable_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("timeout.intent_id", intent_id)?;
        ensure_non_empty("timeout.escrow_ref_id", escrow_ref_id)?;
        ensure_non_empty("timeout.refund_endpoint_id", refund_endpoint_id)?;
        ensure_height_order("timeout.armed", armed_at_height, executable_at_height)?;
        ensure_height_order(
            "timeout.executable",
            executable_at_height,
            expires_at_height,
        )?;
        let refund_nullifier_root = payload_root(
            "TIMEOUT-REFUND-NULLIFIER",
            &json!({ "intent_id": intent_id, "escrow_ref_id": escrow_ref_id }),
        );
        let proof_root = payload_root("TIMEOUT-REFUND-PROOF", proof);
        let timeout_path_id = id_root(
            "TIMEOUT-REFUND-PATH-ID",
            &[
                HashPart::Str(intent_id),
                HashPart::Str(escrow_ref_id),
                HashPart::Str(&refund_nullifier_root),
                HashPart::Int(executable_at_height as i128),
            ],
        );
        Ok(Self {
            timeout_path_id,
            intent_id: intent_id.to_string(),
            escrow_ref_id: escrow_ref_id.to_string(),
            refund_endpoint_id: refund_endpoint_id.to_string(),
            refund_nullifier_root,
            proof_root,
            armed_at_height,
            executable_at_height,
            expires_at_height,
            status: TimeoutPathStatus::Armed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "timeout_refund_path",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "timeout_path_id": self.timeout_path_id,
            "intent_id": self.intent_id,
            "escrow_ref_id": self.escrow_ref_id,
            "refund_endpoint_id": self.refund_endpoint_id,
            "refund_nullifier_root": self.refund_nullifier_root,
            "proof_root": self.proof_root,
            "armed_at_height": self.armed_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("timeout.timeout_path_id", &self.timeout_path_id)?;
        ensure_non_empty("timeout.intent_id", &self.intent_id)?;
        ensure_non_empty("timeout.escrow_ref_id", &self.escrow_ref_id)?;
        ensure_non_empty("timeout.refund_endpoint_id", &self.refund_endpoint_id)?;
        ensure_root("timeout.refund_nullifier_root", &self.refund_nullifier_root)?;
        ensure_root("timeout.proof_root", &self.proof_root)?;
        ensure_height_order(
            "timeout.armed",
            self.armed_at_height,
            self.executable_at_height,
        )?;
        ensure_height_order(
            "timeout.executable",
            self.executable_at_height,
            self.expires_at_height,
        )?;
        Ok(self.timeout_path_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBucket {
    pub bucket_id: String,
    pub route_family: String,
    pub asset_pair_commitment: String,
    pub amount_floor_commitment: String,
    pub amount_ceiling_commitment: String,
    pub privacy_set_size: u64,
    pub decoy_set_root: String,
    pub epoch: u64,
}

impl PrivacyBucket {
    pub fn new(
        route_family: &str,
        asset_pair: &str,
        amount_floor: u64,
        amount_ceiling: u64,
        privacy_set_size: u64,
        epoch: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("bucket.route_family", route_family)?;
        ensure_non_empty("bucket.asset_pair", asset_pair)?;
        if amount_ceiling < amount_floor {
            return Err("bucket amount ceiling must be at least floor".to_string());
        }
        ensure_positive("bucket.privacy_set_size", privacy_set_size)?;
        let asset_pair_commitment = string_root("BUCKET-ASSET-PAIR", asset_pair);
        let amount_floor_commitment = amount_root("BUCKET-AMOUNT-FLOOR", amount_floor, asset_pair);
        let amount_ceiling_commitment =
            amount_root("BUCKET-AMOUNT-CEILING", amount_ceiling, asset_pair);
        let decoy_set_root = payload_root(
            "BUCKET-DECOY-SET",
            &json!({ "route_family": route_family, "asset_pair": asset_pair, "epoch": epoch }),
        );
        let bucket_id = id_root(
            "PRIVACY-BUCKET-ID",
            &[
                HashPart::Str(route_family),
                HashPart::Str(&asset_pair_commitment),
                HashPart::Int(epoch as i128),
            ],
        );
        Ok(Self {
            bucket_id,
            route_family: route_family.to_string(),
            asset_pair_commitment,
            amount_floor_commitment,
            amount_ceiling_commitment,
            privacy_set_size,
            decoy_set_root,
            epoch,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_bucket",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "route_family": self.route_family,
            "asset_pair_commitment": self.asset_pair_commitment,
            "amount_floor_commitment": self.amount_floor_commitment,
            "amount_ceiling_commitment": self.amount_ceiling_commitment,
            "privacy_set_size": self.privacy_set_size,
            "decoy_set_root": self.decoy_set_root,
            "epoch": self.epoch,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("bucket.bucket_id", &self.bucket_id)?;
        ensure_non_empty("bucket.route_family", &self.route_family)?;
        ensure_root("bucket.asset_pair_commitment", &self.asset_pair_commitment)?;
        ensure_root(
            "bucket.amount_floor_commitment",
            &self.amount_floor_commitment,
        )?;
        ensure_root(
            "bucket.amount_ceiling_commitment",
            &self.amount_ceiling_commitment,
        )?;
        ensure_positive("bucket.privacy_set_size", self.privacy_set_size)?;
        ensure_root("bucket.decoy_set_root", &self.decoy_set_root)?;
        Ok(self.bucket_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementLane {
    pub lane_id: String,
    pub source_domain: String,
    pub destination_domain: String,
    pub lane_kind: String,
    pub fee_asset_id: String,
    pub base_fee_units: u64,
    pub capacity_units: u64,
    pub congestion_bps: u64,
    pub finality_blocks: u64,
    pub privacy_floor: u64,
    pub status: SettlementLaneStatus,
}

impl SettlementLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_domain: &str,
        destination_domain: &str,
        lane_kind: &str,
        fee_asset_id: &str,
        base_fee_units: u64,
        capacity_units: u64,
        congestion_bps: u64,
        finality_blocks: u64,
        privacy_floor: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("lane.source_domain", source_domain)?;
        ensure_non_empty("lane.destination_domain", destination_domain)?;
        ensure_non_empty("lane.lane_kind", lane_kind)?;
        ensure_non_empty("lane.fee_asset_id", fee_asset_id)?;
        ensure_positive("lane.capacity_units", capacity_units)?;
        ensure_bps("lane.congestion_bps", congestion_bps)?;
        ensure_positive("lane.finality_blocks", finality_blocks)?;
        ensure_positive("lane.privacy_floor", privacy_floor)?;
        let lane_id = id_root(
            "SETTLEMENT-LANE-ID",
            &[
                HashPart::Str(source_domain),
                HashPart::Str(destination_domain),
                HashPart::Str(lane_kind),
                HashPart::Str(fee_asset_id),
            ],
        );
        Ok(Self {
            lane_id,
            source_domain: source_domain.to_string(),
            destination_domain: destination_domain.to_string(),
            lane_kind: lane_kind.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            base_fee_units,
            capacity_units,
            congestion_bps,
            finality_blocks,
            privacy_floor,
            status: SettlementLaneStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "source_domain": self.source_domain,
            "destination_domain": self.destination_domain,
            "lane_kind": self.lane_kind,
            "fee_asset_id": self.fee_asset_id,
            "base_fee_units": self.base_fee_units,
            "capacity_units": self.capacity_units,
            "congestion_bps": self.congestion_bps,
            "finality_blocks": self.finality_blocks,
            "privacy_floor": self.privacy_floor,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("lane.lane_id", &self.lane_id)?;
        ensure_non_empty("lane.source_domain", &self.source_domain)?;
        ensure_non_empty("lane.destination_domain", &self.destination_domain)?;
        ensure_non_empty("lane.lane_kind", &self.lane_kind)?;
        ensure_non_empty("lane.fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("lane.capacity_units", self.capacity_units)?;
        ensure_bps("lane.congestion_bps", self.congestion_bps)?;
        ensure_positive("lane.finality_blocks", self.finality_blocks)?;
        ensure_positive("lane.privacy_floor", self.privacy_floor)?;
        Ok(self.lane_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRouterRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub disclosure_bps: u64,
    pub published_at_height: u64,
}

impl PublicRouterRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        disclosure_bps: u64,
        published_at_height: u64,
    ) -> PrivateCrossChainIntentRouterResult<Self> {
        ensure_non_empty("public.record_kind", record_kind)?;
        ensure_non_empty("public.subject_id", subject_id)?;
        ensure_bps("public.disclosure_bps", disclosure_bps)?;
        let payload_root = payload_root("PUBLIC-ROUTER-RECORD", payload);
        let record_id = id_root(
            "PUBLIC-ROUTER-RECORD-ID",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&payload_root),
                HashPart::Int(published_at_height as i128),
            ],
        );
        Ok(Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            disclosure_bps,
            published_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_router_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "disclosure_bps": self.disclosure_bps,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        ensure_non_empty("public.record_id", &self.record_id)?;
        ensure_non_empty("public.record_kind", &self.record_kind)?;
        ensure_non_empty("public.subject_id", &self.subject_id)?;
        ensure_root("public.payload_root", &self.payload_root)?;
        ensure_bps("public.disclosure_bps", self.disclosure_bps)?;
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossChainIntentRouterRoots {
    pub config_root: String,
    pub monero_endpoint_root: String,
    pub intent_root: String,
    pub quote_root: String,
    pub solver_root: String,
    pub solver_commitment_root: String,
    pub pq_attestation_root: String,
    pub route_leg_root: String,
    pub settlement_escrow_ref_root: String,
    pub sponsorship_root: String,
    pub timeout_refund_root: String,
    pub privacy_bucket_root: String,
    pub settlement_lane_root: String,
    pub public_record_root: String,
    pub counters_root: String,
}

impl PrivateCrossChainIntentRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_intent_router_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "monero_endpoint_root": self.monero_endpoint_root,
            "intent_root": self.intent_root,
            "quote_root": self.quote_root,
            "solver_root": self.solver_root,
            "solver_commitment_root": self.solver_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "route_leg_root": self.route_leg_root,
            "settlement_escrow_ref_root": self.settlement_escrow_ref_root,
            "sponsorship_root": self.sponsorship_root,
            "timeout_refund_root": self.timeout_refund_root,
            "privacy_bucket_root": self.privacy_bucket_root,
            "settlement_lane_root": self.settlement_lane_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossChainIntentRouterCounters {
    pub monero_endpoint_count: u64,
    pub intent_count: u64,
    pub live_intent_count: u64,
    pub quote_count: u64,
    pub selected_quote_count: u64,
    pub solver_count: u64,
    pub commitment_count: u64,
    pub pq_attestation_count: u64,
    pub route_leg_count: u64,
    pub settlement_escrow_ref_count: u64,
    pub sponsorship_count: u64,
    pub timeout_refund_count: u64,
    pub privacy_bucket_count: u64,
    pub settlement_lane_count: u64,
    pub public_record_count: u64,
    pub sponsored_budget_units: u64,
    pub sponsored_available_units: u64,
}

impl PrivateCrossChainIntentRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_intent_router_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "monero_endpoint_count": self.monero_endpoint_count,
            "intent_count": self.intent_count,
            "live_intent_count": self.live_intent_count,
            "quote_count": self.quote_count,
            "selected_quote_count": self.selected_quote_count,
            "solver_count": self.solver_count,
            "commitment_count": self.commitment_count,
            "pq_attestation_count": self.pq_attestation_count,
            "route_leg_count": self.route_leg_count,
            "settlement_escrow_ref_count": self.settlement_escrow_ref_count,
            "sponsorship_count": self.sponsorship_count,
            "timeout_refund_count": self.timeout_refund_count,
            "privacy_bucket_count": self.privacy_bucket_count,
            "settlement_lane_count": self.settlement_lane_count,
            "public_record_count": self.public_record_count,
            "sponsored_budget_units": self.sponsored_budget_units,
            "sponsored_available_units": self.sponsored_available_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossChainIntentRouterState {
    pub config: PrivateCrossChainIntentRouterConfig,
    pub height: u64,
    pub monero_endpoints: BTreeMap<String, MoneroStealthEndpoint>,
    pub intents: BTreeMap<String, EncryptedCrossChainIntent>,
    pub quotes: BTreeMap<String, RouteQuote>,
    pub solvers: BTreeMap<String, SolverProfile>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub pq_attestations: BTreeMap<String, PqSolverAttestation>,
    pub settlement_escrow_refs: BTreeMap<String, SettlementEscrowRef>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub timeout_refund_paths: BTreeMap<String, TimeoutRefundPath>,
    pub privacy_buckets: BTreeMap<String, PrivacyBucket>,
    pub settlement_lanes: BTreeMap<String, SettlementLane>,
    pub public_records: BTreeMap<String, PublicRouterRecord>,
}

impl PrivateCrossChainIntentRouterState {
    pub fn devnet() -> PrivateCrossChainIntentRouterResult<Self> {
        let mut state = Self {
            config: PrivateCrossChainIntentRouterConfig::devnet(),
            height: PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_HEIGHT,
            monero_endpoints: BTreeMap::new(),
            intents: BTreeMap::new(),
            quotes: BTreeMap::new(),
            solvers: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlement_escrow_refs: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            timeout_refund_paths: BTreeMap::new(),
            privacy_buckets: BTreeMap::new(),
            settlement_lanes: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };

        let monero_bucket = PrivacyBucket::new(
            "monero_entry_private_swap",
            "xmr/dxmr/dusd",
            10_000_000,
            100_000_000,
            384,
            1,
        )?;
        let monero_bucket_id = state.insert_privacy_bucket(monero_bucket)?;
        let contract_bucket = PrivacyBucket::new(
            "private_contract_vault",
            "dusd/private-vault-share",
            1_000_000_000,
            20_000_000_000,
            256,
            1,
        )?;
        let contract_bucket_id = state.insert_privacy_bucket(contract_bucket)?;

        let entry_endpoint = MoneroStealthEndpoint::new(
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_MONERO_NETWORK,
            "entry",
            "devnet-alice-entry",
            &monero_bucket_id,
            state.height + 4,
        )?;
        let entry_endpoint_id = state.insert_monero_endpoint(entry_endpoint)?;
        let exit_endpoint = MoneroStealthEndpoint::new(
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_MONERO_NETWORK,
            "exit",
            "devnet-alice-exit",
            &monero_bucket_id,
            state.height + 18,
        )?;
        let exit_endpoint_id = state.insert_monero_endpoint(exit_endpoint)?;

        let bridge_lane = SettlementLane::new(
            "monero-devnet",
            "nebula-private-l2",
            "monero_entry",
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_FEE_ASSET_ID,
            9,
            50_000_000_000,
            1_900,
            8,
            192,
        )?;
        let bridge_lane_id = state.insert_settlement_lane(bridge_lane)?;
        let swap_lane = SettlementLane::new(
            "nebula-private-l2",
            "nebula-private-vm-devnet",
            "private_swap_contract",
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_FEE_ASSET_ID,
            6,
            80_000_000_000,
            2_200,
            3,
            128,
        )?;
        let swap_lane_id = state.insert_settlement_lane(swap_lane)?;

        let lane_ids = vec![bridge_lane_id.clone(), swap_lane_id.clone()];
        let asset_ids = vec![
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_XMR_ASSET_ID.to_string(),
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DXMR_ASSET_ID.to_string(),
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DUSD_ASSET_ID.to_string(),
        ];
        let solver = SolverProfile::new(
            "devnet-cross-chain-fast-solver",
            "devnet-router-operator",
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_FEE_ASSET_ID,
            250_000,
            &lane_ids,
            &asset_ids,
            "devnet-fast-solver-private-endpoint",
            96,
            1_200,
            9_650,
        )?;
        let solver_id = state.insert_solver(solver)?;
        let attestation = PqSolverAttestation::new(
            &solver_id,
            "devnet-fast-solver-ml-kem-1024-key",
            &json!({"ml_dsa_87": "devnet-signature", "slh_dsa": "devnet-backstop"}),
            &[
                "monero-entry".to_string(),
                "private-swap".to_string(),
                "contract-call".to_string(),
                "timeout-refund".to_string(),
            ],
            &json!({"deterministic_build": true, "tee": "none-devnet"}),
            256,
            state.height,
            state.height + 7_200,
        )?;
        let attestation_id = state.insert_pq_attestation(attestation)?;

        let intent = EncryptedCrossChainIntent::new(
            "devnet-alice-wallet",
            CrossChainIntentKind::Composite,
            RouterPrivacyMode::SolverScoped,
            "monero-devnet",
            "nebula-private-vm-devnet",
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_XMR_ASSET_ID,
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DUSD_ASSET_ID,
            42_000_000,
            7_500_000_000,
            &monero_bucket_id,
            &json!({
                "flow": "monero-entry-swap-vault-call",
                "entry": entry_endpoint_id,
                "exit": exit_endpoint_id,
            }),
            &json!({
                "families": ["monero_entry", "private_swap", "private_contract_call"],
                "speed": "fast",
                "fee": "sponsored",
            }),
            &entry_endpoint_id,
            &exit_endpoint_id,
            "devnet-alice-refund-note",
            18_000,
            state.height,
            state.height + state.config.intent_ttl_blocks,
            1,
        )?;
        let intent_id = state.insert_intent(intent)?;

        let entry_leg = PrivateRouteLeg::new(
            0,
            RouteLegKind::MoneroEntry,
            "monero-devnet",
            "nebula-private-l2",
            "devnet-monero-entry-adapter",
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_XMR_ASSET_ID,
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DXMR_ASSET_ID,
            42_000_000,
            41_980_000,
            4_000,
            &monero_bucket_id,
            &json!({"stealth_endpoint": entry_endpoint_id}),
            &json!({"ring_members": 16, "reserve": "devnet-bridge-reserve"}),
        )?;
        let swap_leg = PrivateRouteLeg::new(
            1,
            RouteLegKind::PrivateSwap,
            "nebula-private-l2",
            "nebula-private-l2",
            "devnet-private-swap-adapter",
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DXMR_ASSET_ID,
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DUSD_ASSET_ID,
            41_980_000,
            7_560_000_000,
            5_500,
            &monero_bucket_id,
            &json!({"pool": "dxmr-dusd-shielded-hybrid", "limit": "bucketed"}),
            &json!({"oracle": "medianized-private-oracle", "max_impact_bps": 45}),
        )?;
        let contract_leg = PrivateRouteLeg::new(
            2,
            RouteLegKind::PrivateContractCall,
            "nebula-private-l2",
            "nebula-private-vm-devnet",
            "devnet-private-vault-adapter",
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_DUSD_ASSET_ID,
            "private-vault-share",
            7_560_000_000,
            7_558_000_000,
            2_000,
            &contract_bucket_id,
            &json!({"contract": "shielded-yield-vault", "selector": "deposit_private"}),
            &json!({"health_factor_floor_bps": 15_000, "policy": "no-public-mempool"}),
        )?;
        let quote = RouteQuote::new(
            &intent_id,
            &solver_id,
            &attestation_id,
            &swap_lane_id,
            vec![entry_leg, swap_leg, contract_leg],
            7_550_000_000,
            11_500,
            7_000,
            4_500,
            5,
            9_400,
            9_100,
            "devnet-fast-route-secret",
            &json!({"signature": "devnet-fast-route-pq-signature"}),
            state.height + 1,
            state.height + state.config.quote_ttl_blocks,
        )?;
        let quote_id = state.insert_quote(quote)?;

        let escrow = SettlementEscrowRef::new(
            &intent_id,
            &quote_id,
            "devnet-cross-chain-settlement-escrow",
            &json!({"deposit_nullifier": "devnet-alice-deposit-nullifier"}),
            &json!({"release_note": "devnet-alice-vault-note"}),
            &json!({"refund_note": "devnet-alice-refund-note"}),
            11_500,
            state.height + 1,
            state.height + state.config.settlement_ttl_blocks,
        )?;
        let escrow_ref_id = state.insert_settlement_escrow_ref(escrow)?;

        let commitment = SolverCommitment::new(
            &solver_id,
            &quote_id,
            &intent_id,
            &escrow_ref_id,
            75_000,
            &json!({"commitment": "devnet-solver-route-preimage"}),
            state.height + 1,
            state.height + 6,
        )?;
        state.insert_solver_commitment(commitment)?;

        let sponsorship = LowFeeSponsorship::new(
            "devnet-low-fee-paymaster",
            &swap_lane_id,
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEVNET_FEE_ASSET_ID,
            1_000_000,
            PRIVATE_CROSS_CHAIN_INTENT_ROUTER_DEFAULT_LOW_FEE_REBATE_BPS,
            &json!({"eligible": ["monero_entry", "private_swap"], "max_user_fee_bps": 20}),
            state.height,
            state.height + 7_200,
        )?;
        state.insert_sponsorship(sponsorship)?;

        let timeout = TimeoutRefundPath::new(
            &intent_id,
            &escrow_ref_id,
            &exit_endpoint_id,
            &json!({"refund_proof": "devnet-timeout-refund-proof"}),
            state.height + 1,
            state.height + state.config.refund_delay_blocks,
            state.height + state.config.intent_ttl_blocks + state.config.refund_delay_blocks,
        )?;
        state.insert_timeout_refund_path(timeout)?;

        let boot_record = PublicRouterRecord::new(
            "devnet_bootstrap",
            &intent_id,
            &state.public_record(),
            300,
            state.height,
        )?;
        state.insert_public_record(boot_record)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateCrossChainIntentRouterResult<()> {
        if height < self.height {
            return Err("router height cannot move backwards".to_string());
        }
        self.height = height;
        self.validate().map(|_| ())
    }

    pub fn roots(&self) -> PrivateCrossChainIntentRouterRoots {
        PrivateCrossChainIntentRouterRoots {
            config_root: payload_root("ROUTER-CONFIG", &self.config.public_record()),
            monero_endpoint_root: map_root("ROUTER-MONERO-ENDPOINTS", &self.monero_endpoints),
            intent_root: map_root("ROUTER-INTENTS", &self.intents),
            quote_root: map_root("ROUTER-QUOTES", &self.quotes),
            solver_root: map_root("ROUTER-SOLVERS", &self.solvers),
            solver_commitment_root: map_root("ROUTER-SOLVER-COMMITMENTS", &self.solver_commitments),
            pq_attestation_root: map_root("ROUTER-PQ-ATTESTATIONS", &self.pq_attestations),
            route_leg_root: value_merkle_root("ROUTER-ROUTE-LEGS", self.route_leg_records()),
            settlement_escrow_ref_root: map_root(
                "ROUTER-SETTLEMENT-ESCROW-REFS",
                &self.settlement_escrow_refs,
            ),
            sponsorship_root: map_root("ROUTER-SPONSORSHIPS", &self.sponsorships),
            timeout_refund_root: map_root("ROUTER-TIMEOUT-REFUNDS", &self.timeout_refund_paths),
            privacy_bucket_root: map_root("ROUTER-PRIVACY-BUCKETS", &self.privacy_buckets),
            settlement_lane_root: map_root("ROUTER-SETTLEMENT-LANES", &self.settlement_lanes),
            public_record_root: map_root("ROUTER-PUBLIC-RECORDS", &self.public_records),
            counters_root: payload_root("ROUTER-COUNTERS", &self.counters().public_record()),
        }
    }

    pub fn counters(&self) -> PrivateCrossChainIntentRouterCounters {
        let live_intent_count = self
            .intents
            .values()
            .filter(|intent| intent.status.live())
            .count() as u64;
        let selected_quote_count = self
            .quotes
            .values()
            .filter(|quote| quote.status == QuoteStatus::Selected)
            .count() as u64;
        let route_leg_count = self
            .quotes
            .values()
            .map(|quote| quote.route_legs.len() as u64)
            .sum();
        let sponsored_budget_units = self
            .sponsorships
            .values()
            .map(|sponsorship| sponsorship.budget_units)
            .sum();
        let sponsored_available_units = self
            .sponsorships
            .values()
            .map(LowFeeSponsorship::available_units)
            .sum();
        PrivateCrossChainIntentRouterCounters {
            monero_endpoint_count: self.monero_endpoints.len() as u64,
            intent_count: self.intents.len() as u64,
            live_intent_count,
            quote_count: self.quotes.len() as u64,
            selected_quote_count,
            solver_count: self.solvers.len() as u64,
            commitment_count: self.solver_commitments.len() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            route_leg_count,
            settlement_escrow_ref_count: self.settlement_escrow_refs.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            timeout_refund_count: self.timeout_refund_paths.len() as u64,
            privacy_bucket_count: self.privacy_buckets.len() as u64,
            settlement_lane_count: self.settlement_lanes.len() as u64,
            public_record_count: self.public_records.len() as u64,
            sponsored_budget_units,
            sponsored_available_units,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_cross_chain_intent_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "state_root": private_cross_chain_intent_router_state_root_from_record(
                &json!({
                    "kind": "private_cross_chain_intent_router_state_without_root",
                    "chain_id": CHAIN_ID,
                    "protocol_version": PRIVATE_CROSS_CHAIN_INTENT_ROUTER_PROTOCOL_VERSION,
                    "height": self.height,
                    "config": self.config.public_record(),
                    "roots": roots.public_record(),
                    "counters": self.counters().public_record(),
                })
            ),
        })
    }

    pub fn state_root(&self) -> String {
        private_cross_chain_intent_router_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateCrossChainIntentRouterResult<String> {
        self.config.validate()?;
        if self.intents.len() > PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_INTENTS {
            return Err("router has too many intents".to_string());
        }
        if self.quotes.len() > PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_QUOTES {
            return Err("router has too many quotes".to_string());
        }
        if self.solvers.len() > PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_SOLVERS {
            return Err("router has too many solvers".to_string());
        }
        if self.settlement_lanes.len() > PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_SETTLEMENT_LANES {
            return Err("router has too many settlement lanes".to_string());
        }
        if self.public_records.len() > PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_PUBLIC_RECORDS {
            return Err("router has too many public records".to_string());
        }

        for (id, endpoint) in &self.monero_endpoints {
            ensure_key_matches(id, &endpoint.validate()?, "monero endpoint")?;
        }
        for (id, bucket) in &self.privacy_buckets {
            ensure_key_matches(id, &bucket.validate()?, "privacy bucket")?;
            if bucket.privacy_set_size < self.config.min_privacy_set_size {
                return Err("privacy bucket below configured privacy floor".to_string());
            }
        }
        for (id, lane) in &self.settlement_lanes {
            ensure_key_matches(id, &lane.validate()?, "settlement lane")?;
        }
        for (id, solver) in &self.solvers {
            ensure_key_matches(id, &solver.validate()?, "solver")?;
            if solver.bond_units < self.config.min_solver_bond_units {
                return Err("solver bond below router minimum".to_string());
            }
        }
        for (id, attestation) in &self.pq_attestations {
            ensure_key_matches(id, &attestation.validate()?, "pq attestation")?;
            if !self.solvers.contains_key(&attestation.solver_id) {
                return Err("pq attestation references missing solver".to_string());
            }
        }
        for (id, intent) in &self.intents {
            ensure_key_matches(id, &intent.validate()?, "intent")?;
            if !self
                .monero_endpoints
                .contains_key(&intent.monero_entry_endpoint_id)
            {
                return Err("intent references missing monero entry endpoint".to_string());
            }
            if !self
                .monero_endpoints
                .contains_key(&intent.monero_exit_endpoint_id)
            {
                return Err("intent references missing monero exit endpoint".to_string());
            }
            if intent.max_disclosure_bps > self.config.max_disclosure_bps {
                return Err("intent disclosure exceeds configured privacy budget".to_string());
            }
        }
        for (id, quote) in &self.quotes {
            ensure_key_matches(id, &quote.validate()?, "quote")?;
            if !self.intents.contains_key(&quote.intent_id) {
                return Err("quote references missing intent".to_string());
            }
            if !self.solvers.contains_key(&quote.solver_id) {
                return Err("quote references missing solver".to_string());
            }
            if !self.pq_attestations.contains_key(&quote.attestation_id) {
                return Err("quote references missing pq attestation".to_string());
            }
            if !self.settlement_lanes.contains_key(&quote.lane_id) {
                return Err("quote references missing settlement lane".to_string());
            }
        }
        for (id, escrow) in &self.settlement_escrow_refs {
            ensure_key_matches(id, &escrow.validate()?, "settlement escrow ref")?;
            if !self.intents.contains_key(&escrow.intent_id) {
                return Err("escrow references missing intent".to_string());
            }
            if !self.quotes.contains_key(&escrow.quote_id) {
                return Err("escrow references missing quote".to_string());
            }
        }
        for (id, commitment) in &self.solver_commitments {
            ensure_key_matches(id, &commitment.validate()?, "solver commitment")?;
            if !self.solvers.contains_key(&commitment.solver_id) {
                return Err("commitment references missing solver".to_string());
            }
            if !self.quotes.contains_key(&commitment.quote_id) {
                return Err("commitment references missing quote".to_string());
            }
            if !self
                .settlement_escrow_refs
                .contains_key(&commitment.escrow_ref_id)
            {
                return Err("commitment references missing escrow".to_string());
            }
        }
        for (id, sponsorship) in &self.sponsorships {
            ensure_key_matches(id, &sponsorship.validate()?, "sponsorship")?;
            if sponsorship.rebate_bps > self.config.max_sponsor_share_bps {
                return Err("sponsorship rebate exceeds configured sponsor share".to_string());
            }
        }
        for (id, timeout) in &self.timeout_refund_paths {
            ensure_key_matches(id, &timeout.validate()?, "timeout refund path")?;
            if !self.intents.contains_key(&timeout.intent_id) {
                return Err("timeout references missing intent".to_string());
            }
            if !self
                .settlement_escrow_refs
                .contains_key(&timeout.escrow_ref_id)
            {
                return Err("timeout references missing escrow".to_string());
            }
        }
        for (id, record) in &self.public_records {
            ensure_key_matches(id, &record.validate()?, "public record")?;
            if record.disclosure_bps > self.config.max_disclosure_bps {
                return Err("public record disclosure exceeds configured budget".to_string());
            }
        }
        Ok(self.state_root())
    }

    pub fn insert_monero_endpoint(
        &mut self,
        endpoint: MoneroStealthEndpoint,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = endpoint.validate()?;
        self.monero_endpoints.insert(id.clone(), endpoint);
        Ok(id)
    }

    pub fn insert_intent(
        &mut self,
        intent: EncryptedCrossChainIntent,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = intent.validate()?;
        self.intents.insert(id.clone(), intent);
        Ok(id)
    }

    pub fn insert_quote(
        &mut self,
        quote: RouteQuote,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = quote.validate()?;
        self.quotes.insert(id.clone(), quote);
        Ok(id)
    }

    pub fn insert_solver(
        &mut self,
        solver: SolverProfile,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = solver.validate()?;
        self.solvers.insert(id.clone(), solver);
        Ok(id)
    }

    pub fn insert_solver_commitment(
        &mut self,
        commitment: SolverCommitment,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = commitment.validate()?;
        self.solver_commitments.insert(id.clone(), commitment);
        Ok(id)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqSolverAttestation,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = attestation.validate()?;
        self.pq_attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn insert_settlement_escrow_ref(
        &mut self,
        escrow: SettlementEscrowRef,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = escrow.validate()?;
        self.settlement_escrow_refs.insert(id.clone(), escrow);
        Ok(id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeSponsorship,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = sponsorship.validate()?;
        self.sponsorships.insert(id.clone(), sponsorship);
        Ok(id)
    }

    pub fn insert_timeout_refund_path(
        &mut self,
        timeout: TimeoutRefundPath,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = timeout.validate()?;
        self.timeout_refund_paths.insert(id.clone(), timeout);
        Ok(id)
    }

    pub fn insert_privacy_bucket(
        &mut self,
        bucket: PrivacyBucket,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = bucket.validate()?;
        self.privacy_buckets.insert(id.clone(), bucket);
        Ok(id)
    }

    pub fn insert_settlement_lane(
        &mut self,
        lane: SettlementLane,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = lane.validate()?;
        self.settlement_lanes.insert(id.clone(), lane);
        Ok(id)
    }

    pub fn insert_public_record(
        &mut self,
        record: PublicRouterRecord,
    ) -> PrivateCrossChainIntentRouterResult<String> {
        let id = record.validate()?;
        self.public_records.insert(id.clone(), record);
        Ok(id)
    }

    fn route_leg_records(&self) -> Vec<Value> {
        self.quotes
            .values()
            .flat_map(|quote| quote.route_legs.iter().map(PrivateRouteLeg::public_record))
            .collect::<Vec<_>>()
    }
}

pub fn private_cross_chain_intent_router_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-CROSS-CHAIN-INTENT-ROUTER-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-CHAIN-INTENT-ROUTER-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-CHAIN-INTENT-ROUTER-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let set = values.iter().cloned().collect::<BTreeSet<_>>();
    let leaves = set.into_iter().map(Value::String).collect::<Vec<_>>();
    value_merkle_root(domain, leaves)
}

fn amount_root(domain: &str, value: u64, salt: &str) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-CHAIN-INTENT-ROUTER-{domain}"),
        &[HashPart::Int(value as i128), HashPart::Str(salt)],
        32,
    )
}

fn id_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-CHAIN-INTENT-ROUTER-{domain}"),
        parts,
        32,
    )
}

fn value_merkle_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-CROSS-CHAIN-INTENT-ROUTER-{domain}"),
        &leaves,
    )
}

trait RouterPublicRecord {
    fn public_record(&self) -> Value;
}

impl RouterPublicRecord for MoneroStealthEndpoint {
    fn public_record(&self) -> Value {
        MoneroStealthEndpoint::public_record(self)
    }
}

impl RouterPublicRecord for EncryptedCrossChainIntent {
    fn public_record(&self) -> Value {
        EncryptedCrossChainIntent::public_record(self)
    }
}

impl RouterPublicRecord for RouteQuote {
    fn public_record(&self) -> Value {
        RouteQuote::public_record(self)
    }
}

impl RouterPublicRecord for SolverProfile {
    fn public_record(&self) -> Value {
        SolverProfile::public_record(self)
    }
}

impl RouterPublicRecord for SolverCommitment {
    fn public_record(&self) -> Value {
        SolverCommitment::public_record(self)
    }
}

impl RouterPublicRecord for PqSolverAttestation {
    fn public_record(&self) -> Value {
        PqSolverAttestation::public_record(self)
    }
}

impl RouterPublicRecord for SettlementEscrowRef {
    fn public_record(&self) -> Value {
        SettlementEscrowRef::public_record(self)
    }
}

impl RouterPublicRecord for LowFeeSponsorship {
    fn public_record(&self) -> Value {
        LowFeeSponsorship::public_record(self)
    }
}

impl RouterPublicRecord for TimeoutRefundPath {
    fn public_record(&self) -> Value {
        TimeoutRefundPath::public_record(self)
    }
}

impl RouterPublicRecord for PrivacyBucket {
    fn public_record(&self) -> Value {
        PrivacyBucket::public_record(self)
    }
}

impl RouterPublicRecord for SettlementLane {
    fn public_record(&self) -> Value {
        SettlementLane::public_record(self)
    }
}

impl RouterPublicRecord for PublicRouterRecord {
    fn public_record(&self) -> Value {
        PublicRouterRecord::public_record(self)
    }
}

fn map_root<T: RouterPublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value.public_record() }))
        .collect::<Vec<_>>();
    value_merkle_root(domain, leaves)
}

fn ensure_non_empty(label: &str, value: &str) -> PrivateCrossChainIntentRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PrivateCrossChainIntentRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PrivateCrossChainIntentRouterResult<()> {
    if value > PRIVATE_CROSS_CHAIN_INTENT_ROUTER_MAX_BPS {
        return Err(format!("{label} exceeds bps maximum"));
    }
    Ok(())
}

fn ensure_height_order(
    label: &str,
    start: u64,
    end: u64,
) -> PrivateCrossChainIntentRouterResult<()> {
    if end <= start {
        return Err(format!("{label} end height must be after start height"));
    }
    Ok(())
}

fn ensure_root(label: &str, value: &str) -> PrivateCrossChainIntentRouterResult<()> {
    ensure_non_empty(label, value)?;
    if value.len() != 64 {
        return Err(format!("{label} must be a 32-byte hex root"));
    }
    if !value.chars().all(|item| item.is_ascii_hexdigit()) {
        return Err(format!("{label} must be hex encoded"));
    }
    Ok(())
}

fn ensure_key_matches(
    key: &str,
    computed: &str,
    label: &str,
) -> PrivateCrossChainIntentRouterResult<()> {
    if key != computed {
        return Err(format!("{label} map key mismatch"));
    }
    Ok(())
}
