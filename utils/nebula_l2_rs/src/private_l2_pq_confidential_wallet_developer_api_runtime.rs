use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialWalletDeveloperApiRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-wallet-developer-api-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-wallet-developer-api-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_VIEW_KEY_SUITE: &str =
    "confidential-view-key-selective-disclosure-policy-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_PRECONFIRMATION_SUITE: &str =
    "fast-private-l2-preconfirmation-receipt-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletApiRequestKind {
    PrivateTokenTransfer,
    SmartContractCall,
    MoneroBridgeExit,
    MoneroBridgeDeposit,
    FeeSponsorship,
    PqSessionAuthorization,
    ViewKeyDisclosure,
    LowFeeBatch,
    PreconfirmationReceipt,
}

impl WalletApiRequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTokenTransfer => "private_token_transfer",
            Self::SmartContractCall => "smart_contract_call",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::PqSessionAuthorization => "pq_session_authorization",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::LowFeeBatch => "low_fee_batch",
            Self::PreconfirmationReceipt => "preconfirmation_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Drafted,
    Validated,
    Planned,
    Batched,
    Preconfirmed,
    Rejected,
}

impl RequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Validated => "validated",
            Self::Planned => "planned",
            Self::Batched => "batched",
            Self::Preconfirmed => "preconfirmed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    None,
    WalletOnly,
    AuditorOnly,
    Counterparty,
    Sponsor,
    Regulator,
    PublicReceipt,
}

impl DisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WalletOnly => "wallet_only",
            Self::AuditorOnly => "auditor_only",
            Self::Counterparty => "counterparty",
            Self::Sponsor => "sponsor",
            Self::Regulator => "regulator",
            Self::PublicReceipt => "public_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStrategy {
    None,
    SameAssetNetting,
    ContractCallAggregation,
    BridgeExitAggregation,
    SponsoredBundle,
    PreconfirmationLane,
}

impl BatchStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SameAssetNetting => "same_asset_netting",
            Self::ContractCallAggregation => "contract_call_aggregation",
            Self::BridgeExitAggregation => "bridge_exit_aggregation",
            Self::SponsoredBundle => "sponsored_bundle",
            Self::PreconfirmationLane => "preconfirmation_lane",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub view_key_suite: String,
    pub preconfirmation_suite: String,
    pub default_fee_asset_id: String,
    pub max_memo_bytes: u16,
    pub max_contract_calldata_bytes: u32,
    pub max_batch_items: usize,
    pub max_disclosure_labels: usize,
    pub min_pq_security_bits: u16,
    pub min_session_weight: u64,
    pub default_fee_limit_units: u64,
    pub bridge_exit_min_amount: u64,
    pub bridge_deposit_min_amount: u64,
    pub low_fee_target_bps: u16,
    pub sponsor_max_fee_bps: u16,
    pub preconfirmation_ttl_blocks: u64,
    pub allow_sponsored_fees: bool,
    pub allow_low_fee_batching: bool,
    pub require_view_policy: bool,
    pub require_pq_session: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_SCHEMA_VERSION,
            l2_network: PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            view_key_suite: PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_VIEW_KEY_SUITE
                .to_string(),
            preconfirmation_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_PRECONFIRMATION_SUITE
                    .to_string(),
            default_fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_FEE_ASSET_ID
                    .to_string(),
            max_memo_bytes: 160,
            max_contract_calldata_bytes: 32_768,
            max_batch_items: 512,
            max_disclosure_labels: 32,
            min_pq_security_bits: 256,
            min_session_weight: 2,
            default_fee_limit_units: 25_000,
            bridge_exit_min_amount: 10_000,
            bridge_deposit_min_amount: 10_000,
            low_fee_target_bps: 12,
            sponsor_max_fee_bps: 20,
            preconfirmation_ttl_blocks: 12,
            allow_sponsored_fees: true,
            allow_low_fee_batching: true,
            require_view_policy: true,
            require_pq_session: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("default_fee_asset_id", &self.default_fee_asset_id)?;
        ensure_positive("max_memo_bytes", self.max_memo_bytes as u64)?;
        ensure_positive(
            "max_contract_calldata_bytes",
            self.max_contract_calldata_bytes as u64,
        )?;
        ensure_positive("max_batch_items", self.max_batch_items as u64)?;
        ensure_positive("min_session_weight", self.min_session_weight)?;
        ensure_positive("default_fee_limit_units", self.default_fee_limit_units)?;
        ensure_bps("low_fee_target_bps", self.low_fee_target_bps)?;
        ensure_bps("sponsor_max_fee_bps", self.sponsor_max_fee_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyPolicy {
    pub policy_id: String,
    pub owner_commitment: String,
    pub default_scope: DisclosureScope,
    pub allowed_scopes: BTreeSet<DisclosureScope>,
    pub auditor_commitments: BTreeSet<String>,
    pub revealed_fields: BTreeSet<String>,
    pub redaction_root: String,
    pub expires_at_height: u64,
}

impl ViewKeyPolicy {
    pub fn new(
        owner_label: &str,
        default_scope: DisclosureScope,
        allowed_scopes: BTreeSet<DisclosureScope>,
        revealed_fields: BTreeSet<String>,
        expires_at_height: u64,
    ) -> Self {
        let owner_commitment = wallet_api_label_commitment("VIEW-OWNER", owner_label);
        let redaction_root = wallet_api_values_root("VIEW-REDACTIONS", revealed_fields.iter());
        let policy_id = wallet_api_id(
            "VIEW-POLICY-ID",
            &[
                HashPart::Str(&owner_commitment),
                HashPart::Str(default_scope.as_str()),
                HashPart::Str(&redaction_root),
                HashPart::U64(expires_at_height),
            ],
        );
        Self {
            policy_id,
            owner_commitment,
            default_scope,
            allowed_scopes,
            auditor_commitments: BTreeSet::new(),
            revealed_fields,
            redaction_root,
            expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "owner_commitment": self.owner_commitment,
            "default_scope": self.default_scope,
            "allowed_scopes": self.allowed_scopes,
            "auditor_commitments": self.auditor_commitments,
            "revealed_fields": self.revealed_fields,
            "redaction_root": self.redaction_root,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        wallet_api_payload_root("VIEW-KEY-POLICY", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("policy_id", &self.policy_id)?;
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        ensure_nonempty("redaction_root", &self.redaction_root)?;
        if self.allowed_scopes.is_empty() {
            return Err("view key policy must allow at least one disclosure scope".to_string());
        }
        if !self.allowed_scopes.contains(&self.default_scope) {
            return Err("view key default scope must be included in allowed scopes".to_string());
        }
        if self.revealed_fields.len() > config.max_disclosure_labels {
            return Err("view key policy reveals too many fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSessionAuthorizationRequest {
    pub wallet_commitment: String,
    pub developer_key_commitment: String,
    pub session_policy_root: String,
    pub allowed_kinds: BTreeSet<WalletApiRequestKind>,
    pub security_bits: u16,
    pub signature_weight: u64,
    pub expires_at_height: u64,
    pub replay_guard: String,
}

impl PqSessionAuthorizationRequest {
    pub fn demo() -> Self {
        let allowed_kinds = BTreeSet::from([
            WalletApiRequestKind::PrivateTokenTransfer,
            WalletApiRequestKind::SmartContractCall,
            WalletApiRequestKind::MoneroBridgeExit,
            WalletApiRequestKind::FeeSponsorship,
        ]);
        Self {
            wallet_commitment: wallet_api_label_commitment("WALLET", "demo-wallet"),
            developer_key_commitment: wallet_api_label_commitment("DEVELOPER-KEY", "demo-sdk"),
            session_policy_root: wallet_api_payload_root(
                "SESSION-POLICY",
                &json!({"spend_limit_units": 250_000_u64, "kinds": allowed_kinds}),
            ),
            allowed_kinds,
            security_bits: 256,
            signature_weight: 3,
            expires_at_height: 1_276_120,
            replay_guard: wallet_api_label_commitment("REPLAY-GUARD", "demo-session"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn request_id(&self) -> String {
        wallet_api_payload_root("PQ-SESSION-AUTHORIZATION-REQUEST", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("wallet_commitment", &self.wallet_commitment)?;
        ensure_nonempty("developer_key_commitment", &self.developer_key_commitment)?;
        ensure_nonempty("session_policy_root", &self.session_policy_root)?;
        ensure_nonempty("replay_guard", &self.replay_guard)?;
        ensure_positive("signature_weight", self.signature_weight)?;
        if self.allowed_kinds.is_empty() {
            return Err("pq session must authorize at least one request kind".to_string());
        }
        if self.security_bits < config.min_pq_security_bits {
            return Err("pq session security bits are below runtime minimum".to_string());
        }
        if self.signature_weight < config.min_session_weight {
            return Err("pq session signature weight is below runtime minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateTokenTransferRequest {
    pub wallet_commitment: String,
    pub asset_id: String,
    pub recipient_commitment: String,
    pub amount_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub nullifier_root: String,
    pub memo_root: String,
    pub fee_limit_units: u64,
    pub view_policy_id: String,
    pub session_id: String,
}

impl PrivateTokenTransferRequest {
    pub fn demo() -> Self {
        Self {
            wallet_commitment: wallet_api_label_commitment("WALLET", "demo-wallet"),
            asset_id: "NEBULA.PRIVATE.TEST".to_string(),
            recipient_commitment: wallet_api_label_commitment("RECIPIENT", "demo-recipient"),
            amount_commitment: wallet_api_label_commitment("AMOUNT", "transfer-42000"),
            input_note_root: wallet_api_values_root("TRANSFER-INPUT-NOTES", ["note-a", "note-b"]),
            output_note_root: wallet_api_values_root("TRANSFER-OUTPUT-NOTES", ["note-c", "note-d"]),
            nullifier_root: wallet_api_values_root(
                "TRANSFER-NULLIFIERS",
                ["nullifier-a", "nullifier-b"],
            ),
            memo_root: wallet_api_payload_root("TRANSFER-MEMO", &json!({"memo": "demo"})),
            fee_limit_units: 1_200,
            view_policy_id: wallet_api_label_commitment("VIEW-POLICY", "demo-wallet"),
            session_id: wallet_api_label_commitment("SESSION", "demo-session"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_common_wallet_fields(
            &self.wallet_commitment,
            &self.view_policy_id,
            &self.session_id,
        )?;
        ensure_nonempty("asset_id", &self.asset_id)?;
        ensure_nonempty("recipient_commitment", &self.recipient_commitment)?;
        ensure_nonempty("amount_commitment", &self.amount_commitment)?;
        ensure_nonempty("input_note_root", &self.input_note_root)?;
        ensure_nonempty("output_note_root", &self.output_note_root)?;
        ensure_nonempty("nullifier_root", &self.nullifier_root)?;
        ensure_positive("fee_limit_units", self.fee_limit_units)?;
        if self.fee_limit_units > config.default_fee_limit_units {
            return Err("private transfer fee limit exceeds runtime default cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmartContractCallRequest {
    pub wallet_commitment: String,
    pub contract_commitment: String,
    pub method_selector: String,
    pub calldata_root: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub value_commitment: String,
    pub fee_asset_id: String,
    pub fee_limit_units: u64,
    pub view_policy_id: String,
    pub session_id: String,
}

impl SmartContractCallRequest {
    pub fn demo() -> Self {
        Self {
            wallet_commitment: wallet_api_label_commitment("WALLET", "demo-wallet"),
            contract_commitment: wallet_api_label_commitment("CONTRACT", "demo-contract"),
            method_selector: "swap_private(bytes32,bytes32)".to_string(),
            calldata_root: wallet_api_payload_root(
                "CONTRACT-CALLDATA",
                &json!({"sealed_args": ["arg-root-a", "arg-root-b"]}),
            ),
            state_read_root: wallet_api_values_root("CONTRACT-READS", ["pool-root", "oracle-root"]),
            state_write_root: wallet_api_values_root("CONTRACT-WRITES", ["settlement-root"]),
            value_commitment: wallet_api_label_commitment("VALUE", "zero"),
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_FEE_ASSET_ID
                    .to_string(),
            fee_limit_units: 3_500,
            view_policy_id: wallet_api_label_commitment("VIEW-POLICY", "demo-wallet"),
            session_id: wallet_api_label_commitment("SESSION", "demo-session"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_common_wallet_fields(
            &self.wallet_commitment,
            &self.view_policy_id,
            &self.session_id,
        )?;
        ensure_nonempty("contract_commitment", &self.contract_commitment)?;
        ensure_nonempty("method_selector", &self.method_selector)?;
        ensure_nonempty("calldata_root", &self.calldata_root)?;
        ensure_nonempty("state_read_root", &self.state_read_root)?;
        ensure_nonempty("state_write_root", &self.state_write_root)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("fee_limit_units", self.fee_limit_units)?;
        if self.fee_limit_units > config.default_fee_limit_units {
            return Err("contract call fee limit exceeds runtime default cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroBridgeExitRequest {
    pub wallet_commitment: String,
    pub exit_asset_id: String,
    pub amount_commitment: String,
    pub monero_subaddress_commitment: String,
    pub burn_note_root: String,
    pub withdrawal_proof_root: String,
    pub decoy_set_root: String,
    pub fee_limit_units: u64,
    pub view_policy_id: String,
    pub session_id: String,
}

impl MoneroBridgeExitRequest {
    pub fn demo() -> Self {
        Self {
            wallet_commitment: wallet_api_label_commitment("WALLET", "demo-wallet"),
            exit_asset_id: "XMR.PRIVATE.TEST".to_string(),
            amount_commitment: wallet_api_label_commitment("EXIT-AMOUNT", "250000"),
            monero_subaddress_commitment: wallet_api_label_commitment(
                "MONERO-SUBADDRESS",
                "84demo",
            ),
            burn_note_root: wallet_api_values_root("EXIT-BURN-NOTES", ["burn-note-a"]),
            withdrawal_proof_root: wallet_api_payload_root(
                "EXIT-WITHDRAWAL-PROOF",
                &json!({"proof": "sealed"}),
            ),
            decoy_set_root: wallet_api_values_root(
                "EXIT-DECOYS",
                ["decoy-a", "decoy-b", "decoy-c"],
            ),
            fee_limit_units: 4_000,
            view_policy_id: wallet_api_label_commitment("VIEW-POLICY", "demo-wallet"),
            session_id: wallet_api_label_commitment("SESSION", "demo-session"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, _config: &Config) -> Result<()> {
        ensure_common_wallet_fields(
            &self.wallet_commitment,
            &self.view_policy_id,
            &self.session_id,
        )?;
        ensure_nonempty("exit_asset_id", &self.exit_asset_id)?;
        ensure_nonempty("amount_commitment", &self.amount_commitment)?;
        ensure_nonempty(
            "monero_subaddress_commitment",
            &self.monero_subaddress_commitment,
        )?;
        ensure_nonempty("burn_note_root", &self.burn_note_root)?;
        ensure_nonempty("withdrawal_proof_root", &self.withdrawal_proof_root)?;
        ensure_nonempty("decoy_set_root", &self.decoy_set_root)?;
        ensure_positive("fee_limit_units", self.fee_limit_units)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroBridgeDepositRequest {
    pub wallet_commitment: String,
    pub deposit_asset_id: String,
    pub amount_commitment: String,
    pub monero_tx_commitment: String,
    pub deposit_note_root: String,
    pub confirmation_proof_root: String,
    pub mint_target_commitment: String,
    pub view_policy_id: String,
    pub session_id: String,
}

impl MoneroBridgeDepositRequest {
    pub fn demo() -> Self {
        Self {
            wallet_commitment: wallet_api_label_commitment("WALLET", "demo-wallet"),
            deposit_asset_id: "XMR.PRIVATE.TEST".to_string(),
            amount_commitment: wallet_api_label_commitment("DEPOSIT-AMOUNT", "125000"),
            monero_tx_commitment: wallet_api_label_commitment("MONERO-TX", "demo-tx"),
            deposit_note_root: wallet_api_values_root("DEPOSIT-NOTES", ["deposit-note-a"]),
            confirmation_proof_root: wallet_api_payload_root(
                "DEPOSIT-CONFIRMATION-PROOF",
                &json!({"confirmations": 20_u64}),
            ),
            mint_target_commitment: wallet_api_label_commitment("MINT-TARGET", "demo-wallet"),
            view_policy_id: wallet_api_label_commitment("VIEW-POLICY", "demo-wallet"),
            session_id: wallet_api_label_commitment("SESSION", "demo-session"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, _config: &Config) -> Result<()> {
        ensure_common_wallet_fields(
            &self.wallet_commitment,
            &self.view_policy_id,
            &self.session_id,
        )?;
        ensure_nonempty("deposit_asset_id", &self.deposit_asset_id)?;
        ensure_nonempty("amount_commitment", &self.amount_commitment)?;
        ensure_nonempty("monero_tx_commitment", &self.monero_tx_commitment)?;
        ensure_nonempty("deposit_note_root", &self.deposit_note_root)?;
        ensure_nonempty("confirmation_proof_root", &self.confirmation_proof_root)?;
        ensure_nonempty("mint_target_commitment", &self.mint_target_commitment)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorshipRequest {
    pub wallet_commitment: String,
    pub sponsor_commitment: String,
    pub sponsored_request_id: String,
    pub fee_asset_id: String,
    pub max_sponsor_fee_bps: u16,
    pub sponsor_policy_root: String,
    pub refund_commitment: String,
    pub session_id: String,
}

impl FeeSponsorshipRequest {
    pub fn demo(sponsored_request_id: &str) -> Self {
        Self {
            wallet_commitment: wallet_api_label_commitment("WALLET", "demo-wallet"),
            sponsor_commitment: wallet_api_label_commitment("SPONSOR", "demo-sponsor"),
            sponsored_request_id: sponsored_request_id.to_string(),
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_DEFAULT_FEE_ASSET_ID
                    .to_string(),
            max_sponsor_fee_bps: 10,
            sponsor_policy_root: wallet_api_payload_root(
                "SPONSOR-POLICY",
                &json!({"max_fee_bps": 10_u16}),
            ),
            refund_commitment: wallet_api_label_commitment("REFUND", "demo-wallet"),
            session_id: wallet_api_label_commitment("SESSION", "demo-session"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if !config.allow_sponsored_fees {
            return Err("fee sponsorship is disabled by runtime config".to_string());
        }
        ensure_nonempty("wallet_commitment", &self.wallet_commitment)?;
        ensure_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_nonempty("sponsored_request_id", &self.sponsored_request_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("sponsor_policy_root", &self.sponsor_policy_root)?;
        ensure_nonempty("refund_commitment", &self.refund_commitment)?;
        ensure_nonempty("session_id", &self.session_id)?;
        ensure_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        if self.max_sponsor_fee_bps > config.sponsor_max_fee_bps {
            return Err("sponsor fee exceeds configured maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchRequest {
    pub wallet_commitment: String,
    pub strategy: BatchStrategy,
    pub member_request_ids: BTreeSet<String>,
    pub aggregate_fee_limit_units: u64,
    pub privacy_set_root: String,
    pub batch_proof_root: String,
    pub target_fee_bps: u16,
    pub session_id: String,
}

impl LowFeeBatchRequest {
    pub fn demo(member_request_ids: BTreeSet<String>) -> Self {
        Self {
            wallet_commitment: wallet_api_label_commitment("WALLET", "demo-wallet"),
            strategy: BatchStrategy::PreconfirmationLane,
            member_request_ids,
            aggregate_fee_limit_units: 6_000,
            privacy_set_root: wallet_api_values_root(
                "LOW-FEE-PRIVACY-SET",
                ["cohort-a", "cohort-b"],
            ),
            batch_proof_root: wallet_api_payload_root(
                "LOW-FEE-BATCH-PROOF",
                &json!({"proof": "sealed"}),
            ),
            target_fee_bps: 8,
            session_id: wallet_api_label_commitment("SESSION", "demo-session"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if !config.allow_low_fee_batching {
            return Err("low fee batching is disabled by runtime config".to_string());
        }
        ensure_nonempty("wallet_commitment", &self.wallet_commitment)?;
        ensure_nonempty("privacy_set_root", &self.privacy_set_root)?;
        ensure_nonempty("batch_proof_root", &self.batch_proof_root)?;
        ensure_nonempty("session_id", &self.session_id)?;
        ensure_positive("aggregate_fee_limit_units", self.aggregate_fee_limit_units)?;
        ensure_bps("target_fee_bps", self.target_fee_bps)?;
        if self.member_request_ids.is_empty() {
            return Err("low fee batch must include at least one member request".to_string());
        }
        if self.member_request_ids.len() > config.max_batch_items {
            return Err("low fee batch exceeds configured item limit".to_string());
        }
        if self.target_fee_bps > config.low_fee_target_bps {
            return Err("low fee batch target exceeds configured target bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "request", rename_all = "snake_case")]
pub enum WalletApiRequest {
    PrivateTokenTransfer(PrivateTokenTransferRequest),
    SmartContractCall(SmartContractCallRequest),
    MoneroBridgeExit(MoneroBridgeExitRequest),
    MoneroBridgeDeposit(MoneroBridgeDepositRequest),
    FeeSponsorship(FeeSponsorshipRequest),
    PqSessionAuthorization(PqSessionAuthorizationRequest),
    ViewKeyDisclosure(ViewKeyPolicy),
    LowFeeBatch(LowFeeBatchRequest),
}

impl WalletApiRequest {
    pub fn kind(&self) -> WalletApiRequestKind {
        match self {
            Self::PrivateTokenTransfer(_) => WalletApiRequestKind::PrivateTokenTransfer,
            Self::SmartContractCall(_) => WalletApiRequestKind::SmartContractCall,
            Self::MoneroBridgeExit(_) => WalletApiRequestKind::MoneroBridgeExit,
            Self::MoneroBridgeDeposit(_) => WalletApiRequestKind::MoneroBridgeDeposit,
            Self::FeeSponsorship(_) => WalletApiRequestKind::FeeSponsorship,
            Self::PqSessionAuthorization(_) => WalletApiRequestKind::PqSessionAuthorization,
            Self::ViewKeyDisclosure(_) => WalletApiRequestKind::ViewKeyDisclosure,
            Self::LowFeeBatch(_) => WalletApiRequestKind::LowFeeBatch,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind(),
            "payload": match self {
                Self::PrivateTokenTransfer(request) => request.public_record(),
                Self::SmartContractCall(request) => request.public_record(),
                Self::MoneroBridgeExit(request) => request.public_record(),
                Self::MoneroBridgeDeposit(request) => request.public_record(),
                Self::FeeSponsorship(request) => request.public_record(),
                Self::PqSessionAuthorization(request) => request.public_record(),
                Self::ViewKeyDisclosure(policy) => policy.public_record(),
                Self::LowFeeBatch(request) => request.public_record(),
            }
        })
    }

    pub fn request_id(&self) -> String {
        wallet_api_id(
            "REQUEST-ID",
            &[
                HashPart::Str(self.kind().as_str()),
                HashPart::Json(&self.public_record()),
            ],
        )
    }

    pub fn root(&self) -> String {
        wallet_api_payload_root("REQUEST", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        match self {
            Self::PrivateTokenTransfer(request) => request.validate(config),
            Self::SmartContractCall(request) => request.validate(config),
            Self::MoneroBridgeExit(request) => request.validate(config),
            Self::MoneroBridgeDeposit(request) => request.validate(config),
            Self::FeeSponsorship(request) => request.validate(config),
            Self::PqSessionAuthorization(request) => request.validate(config),
            Self::ViewKeyDisclosure(policy) => policy.validate(config),
            Self::LowFeeBatch(request) => request.validate(config),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletApiPlan {
    pub plan_id: String,
    pub request_id: String,
    pub kind: WalletApiRequestKind,
    pub status: RequestStatus,
    pub request_root: String,
    pub fee_quote_root: String,
    pub disclosure_root: String,
    pub session_root: String,
    pub batch_group_id: String,
    pub dependencies: BTreeSet<String>,
    pub planned_at_height: u64,
}

impl WalletApiPlan {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        wallet_api_payload_root("PLAN", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub plan_id: String,
    pub request_id: String,
    pub sequencer_commitment: String,
    pub promised_height: u64,
    pub expires_at_height: u64,
    pub inclusion_witness_root: String,
    pub fee_lock_root: String,
    pub status: RequestStatus,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        wallet_api_payload_root("PRECONFIRMATION-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub accepted_requests: u64,
    pub rejected_requests: u64,
    pub planned_requests: u64,
    pub batched_requests: u64,
    pub preconfirmation_receipts: u64,
    pub fee_sponsorships: u64,
    pub pq_sessions: u64,
    pub view_key_policies: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        wallet_api_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub request_root: String,
    pub plan_root: String,
    pub preconfirmation_root: String,
    pub view_policy_root: String,
    pub session_root: String,
    pub public_record_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        wallet_api_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub requests: BTreeMap<String, WalletApiRequest>,
    pub plans: BTreeMap<String, WalletApiPlan>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub view_key_policies: BTreeMap<String, ViewKeyPolicy>,
    pub pq_sessions: BTreeMap<String, PqSessionAuthorizationRequest>,
    pub public_records: BTreeMap<String, Value>,
    pub counters: Counters,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            requests: BTreeMap::new(),
            plans: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            view_key_policies: BTreeMap::new(),
            pq_sessions: BTreeMap::new(),
            public_records: BTreeMap::new(),
            counters: Counters::default(),
        })
    }

    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            requests: BTreeMap::new(),
            plans: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            view_key_policies: BTreeMap::new(),
            pq_sessions: BTreeMap::new(),
            public_records: BTreeMap::new(),
            counters: Counters::default(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let policy = demo_view_key_policy();
        let session = PqSessionAuthorizationRequest::demo();
        let transfer = WalletApiRequest::PrivateTokenTransfer(PrivateTokenTransferRequest::demo());
        let call = WalletApiRequest::SmartContractCall(SmartContractCallRequest::demo());
        let exit = WalletApiRequest::MoneroBridgeExit(MoneroBridgeExitRequest::demo());

        let _ = state.register_view_key_policy(policy);
        let _ = state.authorize_pq_session(session);
        let transfer_plan = state.submit_request(transfer, 1_276_010).ok();
        let call_plan = state.submit_request(call, 1_276_011).ok();
        let exit_plan = state.submit_request(exit, 1_276_012).ok();

        let mut batch_members = BTreeSet::new();
        for plan in [transfer_plan, call_plan, exit_plan].iter().flatten() {
            batch_members.insert(plan.request_id.clone());
        }
        if !batch_members.is_empty() {
            let batch = WalletApiRequest::LowFeeBatch(LowFeeBatchRequest::demo(batch_members));
            let _ = state.submit_request(batch, 1_276_013);
        }

        let plan_ids = state.plans.keys().cloned().collect::<Vec<_>>();
        for plan_id in plan_ids {
            let _ = state.issue_preconfirmation(&plan_id, "demo-sequencer", 1_276_014);
        }
        state
    }

    pub fn register_view_key_policy(&mut self, policy: ViewKeyPolicy) -> Result<String> {
        policy.validate(&self.config)?;
        let policy_id = policy.policy_id.clone();
        self.public_records
            .insert(format!("view_policy:{policy_id}"), policy.public_record());
        self.view_key_policies.insert(policy_id.clone(), policy);
        self.counters.view_key_policies = self.counters.view_key_policies.saturating_add(1);
        Ok(policy_id)
    }

    pub fn authorize_pq_session(
        &mut self,
        request: PqSessionAuthorizationRequest,
    ) -> Result<String> {
        request.validate(&self.config)?;
        let session_id = request.request_id();
        self.public_records
            .insert(format!("pq_session:{session_id}"), request.public_record());
        self.pq_sessions.insert(session_id.clone(), request);
        self.counters.pq_sessions = self.counters.pq_sessions.saturating_add(1);
        Ok(session_id)
    }

    pub fn submit_request(
        &mut self,
        request: WalletApiRequest,
        planned_at_height: u64,
    ) -> Result<WalletApiPlan> {
        if let Err(error) = request.validate(&self.config) {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err(error);
        }

        let request_id = request.request_id();
        let request_root = request.root();
        let kind = request.kind();
        let fee_quote_root = self.fee_quote_root(&request);
        let disclosure_root = self.disclosure_root(&request);
        let session_root = self.session_root_for_request(&request);
        let dependencies = self.dependencies_for_request(&request);
        let batch_group_id = wallet_api_id(
            "BATCH-GROUP",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&fee_quote_root),
                HashPart::Str(&disclosure_root),
            ],
        );
        let plan_id = wallet_api_id(
            "PLAN-ID",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&request_root),
                HashPart::U64(planned_at_height),
            ],
        );
        let status = if matches!(kind, WalletApiRequestKind::LowFeeBatch) {
            RequestStatus::Batched
        } else {
            RequestStatus::Planned
        };
        let plan = WalletApiPlan {
            plan_id: plan_id.clone(),
            request_id: request_id.clone(),
            kind,
            status,
            request_root,
            fee_quote_root,
            disclosure_root,
            session_root,
            batch_group_id,
            dependencies,
            planned_at_height,
        };

        self.public_records
            .insert(format!("request:{request_id}"), request.public_record());
        self.public_records
            .insert(format!("plan:{plan_id}"), plan.public_record());
        self.requests.insert(request_id, request);
        self.plans.insert(plan_id, plan.clone());
        self.counters.accepted_requests = self.counters.accepted_requests.saturating_add(1);
        self.counters.planned_requests = self.counters.planned_requests.saturating_add(1);
        if matches!(kind, WalletApiRequestKind::LowFeeBatch) {
            self.counters.batched_requests = self.counters.batched_requests.saturating_add(1);
        }
        if matches!(kind, WalletApiRequestKind::FeeSponsorship) {
            self.counters.fee_sponsorships = self.counters.fee_sponsorships.saturating_add(1);
        }
        Ok(plan)
    }

    pub fn issue_preconfirmation(
        &mut self,
        plan_id: &str,
        sequencer_label: &str,
        promised_height: u64,
    ) -> Result<PreconfirmationReceipt> {
        ensure_nonempty("plan_id", plan_id)?;
        ensure_nonempty("sequencer_label", sequencer_label)?;
        let plan = match self.plans.get(plan_id) {
            Some(plan) => plan,
            None => return Err("cannot preconfirm unknown wallet api plan".to_string()),
        };
        let sequencer_commitment = wallet_api_label_commitment("SEQUENCER", sequencer_label);
        let expires_at_height =
            promised_height.saturating_add(self.config.preconfirmation_ttl_blocks);
        let inclusion_witness_root = wallet_api_payload_root(
            "PRECONFIRMATION-INCLUSION-WITNESS",
            &json!({
                "plan_id": plan.plan_id,
                "request_id": plan.request_id,
                "request_root": plan.request_root
            }),
        );
        let fee_lock_root = wallet_api_payload_root(
            "PRECONFIRMATION-FEE-LOCK",
            &json!({
                "fee_quote_root": plan.fee_quote_root,
                "batch_group_id": plan.batch_group_id
            }),
        );
        let receipt_id = wallet_api_id(
            "PRECONFIRMATION-RECEIPT-ID",
            &[
                HashPart::Str(&plan.plan_id),
                HashPart::Str(&plan.request_id),
                HashPart::Str(&sequencer_commitment),
                HashPart::U64(promised_height),
                HashPart::Str(&inclusion_witness_root),
            ],
        );
        let receipt = PreconfirmationReceipt {
            receipt_id: receipt_id.clone(),
            plan_id: plan.plan_id.clone(),
            request_id: plan.request_id.clone(),
            sequencer_commitment,
            promised_height,
            expires_at_height,
            inclusion_witness_root,
            fee_lock_root,
            status: RequestStatus::Preconfirmed,
        };
        self.public_records.insert(
            format!("preconfirmation:{receipt_id}"),
            receipt.public_record(),
        );
        self.preconfirmation_receipts
            .insert(receipt_id, receipt.clone());
        self.counters.preconfirmation_receipts =
            self.counters.preconfirmation_receipts.saturating_add(1);
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            request_root: wallet_api_records_root(
                "REQUESTS",
                self.requests.values().map(WalletApiRequest::public_record),
            ),
            plan_root: wallet_api_records_root(
                "PLANS",
                self.plans.values().map(WalletApiPlan::public_record),
            ),
            preconfirmation_root: wallet_api_records_root(
                "PRECONFIRMATIONS",
                self.preconfirmation_receipts
                    .values()
                    .map(PreconfirmationReceipt::public_record),
            ),
            view_policy_root: wallet_api_records_root(
                "VIEW-POLICIES",
                self.view_key_policies
                    .values()
                    .map(ViewKeyPolicy::public_record),
            ),
            session_root: wallet_api_records_root(
                "PQ-SESSIONS",
                self.pq_sessions
                    .values()
                    .map(PqSessionAuthorizationRequest::public_record),
            ),
            public_record_root: wallet_api_records_root(
                "PUBLIC-RECORDS",
                self.public_records.values().cloned(),
            ),
            counter_root: self.counters.root(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "requests": self.requests.values().map(WalletApiRequest::public_record).collect::<Vec<_>>(),
            "plans": self.plans.values().map(WalletApiPlan::public_record).collect::<Vec<_>>(),
            "preconfirmation_receipts": self.preconfirmation_receipts.values().map(PreconfirmationReceipt::public_record).collect::<Vec<_>>(),
            "view_key_policies": self.view_key_policies.values().map(ViewKeyPolicy::public_record).collect::<Vec<_>>(),
            "pq_sessions": self.pq_sessions.values().map(PqSessionAuthorizationRequest::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records
        })
    }

    pub fn state_root(&self) -> String {
        wallet_api_payload_root("STATE", &self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "state": self.public_record_without_root(),
            "roots": roots.public_record(),
            "state_root": self.state_root()
        })
    }

    fn fee_quote_root(&self, request: &WalletApiRequest) -> String {
        let record = match request {
            WalletApiRequest::PrivateTokenTransfer(inner) => json!({
                "asset_id": inner.asset_id,
                "fee_limit_units": inner.fee_limit_units,
                "fee_asset_id": self.config.default_fee_asset_id
            }),
            WalletApiRequest::SmartContractCall(inner) => json!({
                "fee_asset_id": inner.fee_asset_id,
                "fee_limit_units": inner.fee_limit_units
            }),
            WalletApiRequest::MoneroBridgeExit(inner) => json!({
                "asset_id": inner.exit_asset_id,
                "fee_limit_units": inner.fee_limit_units
            }),
            WalletApiRequest::MoneroBridgeDeposit(inner) => json!({
                "asset_id": inner.deposit_asset_id,
                "fee_limit_units": self.config.default_fee_limit_units
            }),
            WalletApiRequest::FeeSponsorship(inner) => json!({
                "fee_asset_id": inner.fee_asset_id,
                "max_sponsor_fee_bps": inner.max_sponsor_fee_bps
            }),
            WalletApiRequest::PqSessionAuthorization(_)
            | WalletApiRequest::ViewKeyDisclosure(_) => {
                json!({"fee_asset_id": self.config.default_fee_asset_id, "fee_limit_units": 0_u64})
            }
            WalletApiRequest::LowFeeBatch(inner) => json!({
                "aggregate_fee_limit_units": inner.aggregate_fee_limit_units,
                "target_fee_bps": inner.target_fee_bps
            }),
        };
        wallet_api_payload_root("FEE-QUOTE", &record)
    }

    fn disclosure_root(&self, request: &WalletApiRequest) -> String {
        let record = match request {
            WalletApiRequest::PrivateTokenTransfer(inner) => {
                json!({"view_policy_id": inner.view_policy_id})
            }
            WalletApiRequest::SmartContractCall(inner) => {
                json!({"view_policy_id": inner.view_policy_id})
            }
            WalletApiRequest::MoneroBridgeExit(inner) => {
                json!({"view_policy_id": inner.view_policy_id})
            }
            WalletApiRequest::MoneroBridgeDeposit(inner) => {
                json!({"view_policy_id": inner.view_policy_id})
            }
            WalletApiRequest::FeeSponsorship(inner) => {
                json!({"sponsor_commitment": inner.sponsor_commitment})
            }
            WalletApiRequest::PqSessionAuthorization(inner) => {
                json!({"wallet_commitment": inner.wallet_commitment})
            }
            WalletApiRequest::ViewKeyDisclosure(inner) => inner.public_record(),
            WalletApiRequest::LowFeeBatch(inner) => {
                json!({"privacy_set_root": inner.privacy_set_root})
            }
        };
        wallet_api_payload_root("DISCLOSURE", &record)
    }

    fn session_root_for_request(&self, request: &WalletApiRequest) -> String {
        let record = match request {
            WalletApiRequest::PrivateTokenTransfer(inner) => {
                json!({"session_id": inner.session_id})
            }
            WalletApiRequest::SmartContractCall(inner) => json!({"session_id": inner.session_id}),
            WalletApiRequest::MoneroBridgeExit(inner) => json!({"session_id": inner.session_id}),
            WalletApiRequest::MoneroBridgeDeposit(inner) => json!({"session_id": inner.session_id}),
            WalletApiRequest::FeeSponsorship(inner) => json!({"session_id": inner.session_id}),
            WalletApiRequest::PqSessionAuthorization(inner) => inner.public_record(),
            WalletApiRequest::ViewKeyDisclosure(inner) => json!({"policy_id": inner.policy_id}),
            WalletApiRequest::LowFeeBatch(inner) => json!({"session_id": inner.session_id}),
        };
        wallet_api_payload_root("SESSION-LINK", &record)
    }

    fn dependencies_for_request(&self, request: &WalletApiRequest) -> BTreeSet<String> {
        match request {
            WalletApiRequest::FeeSponsorship(inner) => {
                BTreeSet::from([inner.sponsored_request_id.clone()])
            }
            WalletApiRequest::LowFeeBatch(inner) => inner.member_request_ids.clone(),
            _ => BTreeSet::new(),
        }
    }
}

pub fn demo_config() -> Config {
    Config::devnet()
}

pub fn demo_view_key_policy() -> ViewKeyPolicy {
    let allowed_scopes = BTreeSet::from([
        DisclosureScope::WalletOnly,
        DisclosureScope::AuditorOnly,
        DisclosureScope::Counterparty,
    ]);
    let revealed_fields = BTreeSet::from([
        "asset_id".to_string(),
        "fee_quote_root".to_string(),
        "preconfirmation_status".to_string(),
    ]);
    let mut policy = ViewKeyPolicy::new(
        "demo-wallet",
        DisclosureScope::WalletOnly,
        allowed_scopes,
        revealed_fields,
        1_277_000,
    );
    policy
        .auditor_commitments
        .insert(wallet_api_label_commitment("AUDITOR", "demo-auditor"));
    policy
}

pub fn demo_state() -> State {
    State::demo()
}

pub fn wallet_api_payload_root(domain: &str, payload: &Value) -> String {
    wallet_api_id(domain, &[HashPart::Json(payload)])
}

pub fn wallet_api_label_commitment(domain: &str, label: &str) -> String {
    wallet_api_id(domain, &[HashPart::Str(label)])
}

pub fn wallet_api_records_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(&format!("WALLET-DEVELOPER-API-{domain}"), &leaves)
}

pub fn wallet_api_values_root<I, S>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let leaves = values
        .into_iter()
        .map(|value| {
            json!({"value_commitment": wallet_api_label_commitment(domain, value.as_ref())})
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("WALLET-DEVELOPER-API-{domain}"), &leaves)
}

pub fn wallet_api_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut all_parts = Vec::with_capacity(parts.len() + 2);
    all_parts.push(HashPart::Str(CHAIN_ID));
    all_parts.push(HashPart::Str(PROTOCOL_VERSION));
    for part in parts {
        all_parts.push(match part {
            HashPart::Bytes(value) => HashPart::Bytes(*value),
            HashPart::Str(value) => HashPart::Str(*value),
            HashPart::U64(value) => HashPart::U64(*value),
            HashPart::Int(value) => HashPart::Int(*value),
            HashPart::Json(value) => HashPart::Json(*value),
        });
    }
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-WALLET-DEVELOPER-API-{domain}"),
        &all_parts,
        32,
    )
}

fn ensure_common_wallet_fields(
    wallet_commitment: &str,
    view_policy_id: &str,
    session_id: &str,
) -> Result<()> {
    ensure_nonempty("wallet_commitment", wallet_commitment)?;
    ensure_nonempty("view_policy_id", view_policy_id)?;
    ensure_nonempty("session_id", session_id)
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be greater than zero"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u16) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_WALLET_DEVELOPER_API_RUNTIME_MAX_BPS {
        Err(format!("{field} must be at most 10000 bps"))
    } else {
        Ok(())
    }
}
