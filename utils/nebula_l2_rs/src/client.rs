use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        account_record, crypto_policy_root, public_key_for_label, sign_authorization,
        sign_network_authorization, sign_recovery_authorization, verify_authorization,
        verify_network_authorization, verify_recovery_authorization, Authorization, CryptoRole,
        RecoveryAuthorization,
    },
    fees::{fee_quote, FeeMarketResource, FeeQuote, LowFeeLane},
    hash::{domain_hash, json_size, merkle_root, HashPart},
    rpc::{
        rpc_public_metadata_root, RpcMethod, RpcReceipt, RpcRequest,
        RPC_DEFAULT_MAX_RESPONSE_BYTES, RPC_DEFAULT_RECEIPT_TTL_BLOCKS,
    },
    workload::{WorkloadIntent, WorkloadIntentKind},
    CHAIN_ID, DEVNET_AUTH_BYTES, DEVNET_BRIDGE_ATTESTATION_BYTES, DEVNET_PRIVACY_PROOF_BYTES,
    TARGET_BLOCK_MS,
};

pub type ClientResult<T> = Result<T, String>;

pub const CLIENT_PROTOCOL_VERSION: &str = "nebula-l2-client-sdk-v1";
pub const CLIENT_DEFAULT_SESSION_TTL_BLOCKS: u64 = 720;
pub const CLIENT_DEFAULT_TX_TTL_BLOCKS: u64 = 12;
pub const CLIENT_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const CLIENT_DEFAULT_MAX_BATCH_ENVELOPES: usize = 128;
pub const CLIENT_DEFAULT_MAX_PAYLOAD_BYTES: u64 = 64 * 1024;
pub const CLIENT_DEFAULT_MAX_FEE_UNITS: u64 = 1;
pub const CLIENT_ACCOUNT_AUTH_DOMAIN: &str = "client_tx_envelope";
pub const CLIENT_SESSION_AUTH_DOMAIN: &str = "client_session";
pub const CLIENT_BATCH_AUTH_DOMAIN: &str = "client_submission_batch";
pub const CLIENT_RECOVERY_AUTH_DOMAIN: &str = "client_recovery_envelope";
pub const CLIENT_NETWORK_AUTH_DOMAIN: &str = "client_network_envelope";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientPrivacyMode {
    PublicRootOnly,
    MetadataMinimized,
    Shielded,
    FullyPrivate,
}

impl ClientPrivacyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicRootOnly => "public_root_only",
            Self::MetadataMinimized => "metadata_minimized",
            Self::Shielded => "shielded",
            Self::FullyPrivate => "fully_private",
        }
    }

    pub fn from_workload_class(privacy_class: &str) -> Self {
        match privacy_class {
            "shielded" => Self::Shielded,
            "metadata_minimized" => Self::MetadataMinimized,
            "fully_private" => Self::FullyPrivate,
            _ => Self::PublicRootOnly,
        }
    }

    pub fn stores_payload_root_only(&self) -> bool {
        matches!(
            self,
            Self::MetadataMinimized | Self::Shielded | Self::FullyPrivate
        )
    }
}

impl Default for ClientPrivacyMode {
    fn default() -> Self {
        Self::Shielded
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIntentStatus {
    Draft,
    Signed,
    Quoted,
    Submitted,
    Accepted,
    Included,
    Finalized,
    Failed,
    Expired,
}

impl ClientIntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Signed => "signed",
            Self::Quoted => "quoted",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Included => "included",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized | Self::Failed | Self::Expired)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTxKind {
    PrivateTransfer,
    AssetMint,
    AssetBurn,
    DefiCall,
    AmmSwap,
    AmmLiquidityAdd,
    LendingBorrow,
    LendingRepay,
    ContractCall,
    WasmCall,
    PaymasterSponsoredCall,
    MoneroBridgeDeposit,
    MoneroBridgeWithdrawal,
    MoneroBridgeAction,
    OracleUpdate,
    ProofJob,
    FeeQuote,
    RpcSubmission,
}

impl ClientTxKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::AssetMint => "asset_mint",
            Self::AssetBurn => "asset_burn",
            Self::DefiCall => "defi_call",
            Self::AmmSwap => "amm_swap",
            Self::AmmLiquidityAdd => "amm_liquidity_add",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::ContractCall => "contract_call",
            Self::WasmCall => "wasm_call",
            Self::PaymasterSponsoredCall => "paymaster_sponsored_call",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::MoneroBridgeWithdrawal => "monero_bridge_withdrawal",
            Self::MoneroBridgeAction => "monero_bridge_action",
            Self::OracleUpdate => "oracle_update",
            Self::ProofJob => "proof_job",
            Self::FeeQuote => "fee_quote",
            Self::RpcSubmission => "rpc_submission",
        }
    }

    pub fn from_workload_kind(kind: &WorkloadIntentKind) -> Self {
        match kind {
            WorkloadIntentKind::PrivateTransfer => Self::PrivateTransfer,
            WorkloadIntentKind::AssetMint => Self::AssetMint,
            WorkloadIntentKind::AssetBurn => Self::AssetBurn,
            WorkloadIntentKind::AmmSwap => Self::AmmSwap,
            WorkloadIntentKind::AmmLiquidityAdd => Self::AmmLiquidityAdd,
            WorkloadIntentKind::LendingBorrow => Self::LendingBorrow,
            WorkloadIntentKind::LendingRepay => Self::LendingRepay,
            WorkloadIntentKind::ContractCall => Self::ContractCall,
            WorkloadIntentKind::WasmCall => Self::WasmCall,
            WorkloadIntentKind::PaymasterSponsoredCall => Self::PaymasterSponsoredCall,
            WorkloadIntentKind::BridgeDeposit => Self::MoneroBridgeDeposit,
            WorkloadIntentKind::BridgeWithdrawal => Self::MoneroBridgeWithdrawal,
            WorkloadIntentKind::OracleUpdate => Self::OracleUpdate,
            WorkloadIntentKind::ProofJob => Self::ProofJob,
        }
    }

    pub fn default_privacy_mode(&self) -> ClientPrivacyMode {
        match self {
            Self::PrivateTransfer
            | Self::AmmSwap
            | Self::PaymasterSponsoredCall
            | Self::MoneroBridgeDeposit
            | Self::MoneroBridgeWithdrawal
            | Self::MoneroBridgeAction => ClientPrivacyMode::Shielded,
            Self::DefiCall
            | Self::AmmLiquidityAdd
            | Self::LendingBorrow
            | Self::LendingRepay
            | Self::ContractCall
            | Self::WasmCall => ClientPrivacyMode::MetadataMinimized,
            _ => ClientPrivacyMode::PublicRootOnly,
        }
    }

    pub fn default_low_fee_lane(&self) -> Option<LowFeeLane> {
        match self {
            Self::PrivateTransfer => Some(LowFeeLane::privacy_transfers()),
            Self::MoneroBridgeDeposit | Self::MoneroBridgeWithdrawal | Self::MoneroBridgeAction => {
                Some(LowFeeLane::monero_bridge_ops())
            }
            Self::DefiCall
            | Self::AmmSwap
            | Self::AmmLiquidityAdd
            | Self::LendingBorrow
            | Self::LendingRepay
            | Self::ContractCall
            | Self::WasmCall
            | Self::PaymasterSponsoredCall => Some(LowFeeLane::small_defi_calls()),
            _ => None,
        }
    }

    pub fn default_rpc_method(&self) -> RpcMethod {
        match self {
            Self::FeeQuote => RpcMethod::LowFeeQuote,
            _ => RpcMethod::SubmitPrivateTx,
        }
    }

    pub fn requires_bridge_attestation(&self) -> bool {
        matches!(
            self,
            Self::MoneroBridgeDeposit | Self::MoneroBridgeWithdrawal | Self::MoneroBridgeAction
        )
    }

    pub fn requires_privacy_proof(&self, privacy_mode: &ClientPrivacyMode) -> bool {
        matches!(
            privacy_mode,
            ClientPrivacyMode::Shielded | ClientPrivacyMode::FullyPrivate
        ) || matches!(
            self,
            Self::PrivateTransfer
                | Self::AssetBurn
                | Self::DefiCall
                | Self::AmmSwap
                | Self::AmmLiquidityAdd
                | Self::LendingBorrow
                | Self::LendingRepay
                | Self::PaymasterSponsoredCall
                | Self::MoneroBridgeDeposit
                | Self::MoneroBridgeWithdrawal
                | Self::MoneroBridgeAction
        )
    }

    pub fn contract_call_count(&self) -> u64 {
        u64::from(matches!(
            self,
            Self::DefiCall | Self::ContractCall | Self::WasmCall | Self::PaymasterSponsoredCall
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAccountProfile {
    pub account_id: String,
    pub account_label: String,
    pub account_commitment: String,
    pub spend_public_key: String,
    pub spend_public_key_id: String,
    pub recovery_public_key: String,
    pub recovery_public_key_id: String,
    pub network_public_key: String,
    pub network_public_key_id: String,
    pub default_privacy_mode: ClientPrivacyMode,
    pub preferred_fee_asset_id: String,
    pub default_low_fee_lane: Option<LowFeeLane>,
    pub crypto_policy_root: String,
}

impl ClientAccountProfile {
    pub fn new(
        account_label: impl Into<String>,
        default_privacy_mode: ClientPrivacyMode,
        preferred_fee_asset_id: impl Into<String>,
    ) -> Self {
        let account_label = account_label.into();
        let account = account_record(&account_label);
        let spend_key = public_key_for_label(CryptoRole::AccountSignature, &account_label);
        let recovery_key = public_key_for_label(CryptoRole::RecoverySignature, &account_label);
        let network_key = public_key_for_label(CryptoRole::KeyEstablishment, &account_label);
        let account_id = client_account_id(&account_label);
        let account_commitment = client_string_root("CLIENT-ACCOUNT-COMMITMENT", &account_id);
        Self {
            account_id,
            account_label,
            account_commitment,
            spend_public_key: account.spend_public_key,
            spend_public_key_id: spend_key.key_id,
            recovery_public_key: account.recovery_public_key,
            recovery_public_key_id: recovery_key.key_id,
            network_public_key: account.network_public_key,
            network_public_key_id: network_key.key_id,
            default_privacy_mode,
            preferred_fee_asset_id: preferred_fee_asset_id.into(),
            default_low_fee_lane: Some(LowFeeLane::privacy_transfers()),
            crypto_policy_root: crypto_policy_root(),
        }
    }

    pub fn with_low_fee_lane(mut self, lane: Option<LowFeeLane>) -> Self {
        self.default_low_fee_lane = lane;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "client_account_profile",
            "chain_id": CHAIN_ID,
            "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "account_commitment": self.account_commitment,
            "spend_public_key_id": self.spend_public_key_id,
            "spend_public_key_root": client_string_root("CLIENT-SPEND-PUBLIC-KEY", &self.spend_public_key),
            "recovery_public_key_id": self.recovery_public_key_id,
            "recovery_public_key_root": client_string_root("CLIENT-RECOVERY-PUBLIC-KEY", &self.recovery_public_key),
            "network_public_key_id": self.network_public_key_id,
            "network_public_key_root": client_string_root("CLIENT-NETWORK-PUBLIC-KEY", &self.network_public_key),
            "default_privacy_mode": self.default_privacy_mode.as_str(),
            "preferred_fee_asset_id": self.preferred_fee_asset_id,
            "default_low_fee_lane": self.default_low_fee_lane.as_ref().map(LowFeeLane::public_record),
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn account_root(&self) -> String {
        domain_hash(
            "CLIENT-ACCOUNT-PROFILE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSession {
    pub session_id: String,
    pub account_id: String,
    pub account_label: String,
    pub account_commitment: String,
    pub session_nonce_hash: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub next_sequence: u64,
    pub privacy_mode: ClientPrivacyMode,
    pub preferred_fee_asset_id: String,
    pub spend_public_key: String,
    pub recovery_public_key: String,
    pub network_public_key: String,
    pub crypto_policy_root: String,
    pub authorization: Option<Authorization>,
}

impl ClientSession {
    pub fn new(
        profile: &ClientAccountProfile,
        session_nonce: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let session_id = client_session_id(&profile.account_id, session_nonce, opened_at_height);
        Self {
            session_id,
            account_id: profile.account_id.clone(),
            account_label: profile.account_label.clone(),
            account_commitment: profile.account_commitment.clone(),
            session_nonce_hash: client_string_root("CLIENT-SESSION-NONCE", session_nonce),
            opened_at_height,
            expires_at_height: opened_at_height
                .saturating_add(ttl_blocks.max(1).max(CLIENT_DEFAULT_TX_TTL_BLOCKS)),
            next_sequence: 0,
            privacy_mode: profile.default_privacy_mode.clone(),
            preferred_fee_asset_id: profile.preferred_fee_asset_id.clone(),
            spend_public_key: profile.spend_public_key.clone(),
            recovery_public_key: profile.recovery_public_key.clone(),
            network_public_key: profile.network_public_key.clone(),
            crypto_policy_root: profile.crypto_policy_root.clone(),
            authorization: None,
        }
    }

    pub fn signed_by_account(mut self) -> Self {
        self.authorization = Some(sign_authorization(
            &self.account_label,
            CLIENT_SESSION_AUTH_DOMAIN,
            &self.unsigned_record(),
        ));
        self
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }

    pub fn reserve_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }

    pub fn observe_sequence(&mut self, sequence: u64) {
        self.next_sequence = self.next_sequence.max(sequence.saturating_add(1));
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "client_session",
            "chain_id": CHAIN_ID,
            "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            "session_id": self.session_id,
            "account_id": self.account_id,
            "account_commitment": self.account_commitment,
            "session_nonce_hash": self.session_nonce_hash,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_mode": self.privacy_mode.as_str(),
            "preferred_fee_asset_id": self.preferred_fee_asset_id,
            "spend_public_key": self.spend_public_key,
            "recovery_public_key": self.recovery_public_key,
            "network_public_key": self.network_public_key,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("client session record object");
        object.insert(
            "session_root".to_string(),
            Value::String(self.session_root()),
        );
        if let Some(authorization) = &self.authorization {
            insert_authorization_fields(object, authorization);
        }
        record
    }

    pub fn session_root(&self) -> String {
        domain_hash(
            "CLIENT-SESSION",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        self.authorization.as_ref().is_some_and(|authorization| {
            authorization.auth_public_key == self.spend_public_key
                && verify_authorization(
                    &authorization.signer_label,
                    CLIENT_SESSION_AUTH_DOMAIN,
                    &self.unsigned_record(),
                    authorization,
                )
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientTxEnvelope {
    pub tx_id: String,
    pub chain_id: String,
    pub client_protocol_version: String,
    pub tx_kind: ClientTxKind,
    pub tx_kind_name: String,
    pub status: ClientIntentStatus,
    pub session_id: String,
    pub account_id: String,
    pub account_commitment: String,
    pub account_public_key: String,
    pub recovery_public_key: String,
    pub sequence: u64,
    pub target_height: u64,
    pub deadline_height: u64,
    pub payload_kind: String,
    pub payload_root: String,
    pub payload_bytes: u64,
    pub public_metadata_root: String,
    pub privacy_mode: ClientPrivacyMode,
    pub low_fee_lane: Option<LowFeeLane>,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub priority_fee_units: u64,
    pub idempotency_key_hash: String,
    pub rpc_method: RpcMethod,
    pub rpc_method_name: String,
    pub workload_intent_id: Option<String>,
    pub workload_intent_root: Option<String>,
    pub crypto_policy_root: String,
    pub authorization: Option<Authorization>,
    pub network_authorization: Option<Authorization>,
    pub network_authority_public_key: Option<String>,
    pub recovery_authorization: Option<RecoveryAuthorization>,
}

impl ClientTxEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn from_payload(
        session: &ClientSession,
        tx_kind: ClientTxKind,
        payload_kind: impl Into<String>,
        payload: &Value,
        public_metadata: &Value,
        target_height: u64,
        deadline_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        let payload_bytes = json_size(payload) as u64;
        if payload_bytes > CLIENT_DEFAULT_MAX_PAYLOAD_BYTES {
            return Err(format!(
                "client payload is {payload_bytes} bytes; max is {CLIENT_DEFAULT_MAX_PAYLOAD_BYTES}"
            ));
        }
        let payload_root = client_tx_payload_root(&tx_kind, payload);
        Self::from_payload_root(
            session,
            tx_kind,
            payload_kind,
            &payload_root,
            payload_bytes,
            public_metadata,
            target_height,
            deadline_height,
            max_fee_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_payload_root(
        session: &ClientSession,
        tx_kind: ClientTxKind,
        payload_kind: impl Into<String>,
        payload_root: &str,
        payload_bytes: u64,
        public_metadata: &Value,
        target_height: u64,
        deadline_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        let sequence = session.next_sequence;
        Self::from_payload_root_with_sequence(
            session,
            sequence,
            tx_kind,
            payload_kind,
            payload_root,
            payload_bytes,
            public_metadata,
            target_height,
            deadline_height,
            max_fee_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_payload_root_with_sequence(
        session: &ClientSession,
        sequence: u64,
        tx_kind: ClientTxKind,
        payload_kind: impl Into<String>,
        payload_root: &str,
        payload_bytes: u64,
        public_metadata: &Value,
        target_height: u64,
        deadline_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        if deadline_height < target_height {
            return Err("client tx deadline must be at or after target height".to_string());
        }
        if payload_bytes > CLIENT_DEFAULT_MAX_PAYLOAD_BYTES {
            return Err(format!(
                "client payload root declares {payload_bytes} bytes; max is {CLIENT_DEFAULT_MAX_PAYLOAD_BYTES}"
            ));
        }
        let public_metadata_root = client_public_metadata_root(public_metadata);
        let tx_id = client_tx_id(
            &session.session_id,
            sequence,
            &tx_kind,
            payload_root,
            &public_metadata_root,
        );
        let idempotency_key_hash = client_string_root("CLIENT-IDEMPOTENCY-KEY", &tx_id);
        let low_fee_lane = tx_kind
            .default_low_fee_lane()
            .or_else(|| fee_lane_from_metadata(public_metadata));
        let privacy_mode = privacy_mode_from_metadata(public_metadata)
            .unwrap_or_else(|| tx_kind.default_privacy_mode())
            .max(session.privacy_mode.clone());
        let rpc_method = tx_kind.default_rpc_method();
        Ok(Self {
            tx_id,
            chain_id: CHAIN_ID.to_string(),
            client_protocol_version: CLIENT_PROTOCOL_VERSION.to_string(),
            tx_kind_name: tx_kind.as_str().to_string(),
            status: ClientIntentStatus::Draft,
            session_id: session.session_id.clone(),
            account_id: session.account_id.clone(),
            account_commitment: session.account_commitment.clone(),
            account_public_key: session.spend_public_key.clone(),
            recovery_public_key: session.recovery_public_key.clone(),
            sequence,
            target_height,
            deadline_height,
            payload_kind: payload_kind.into(),
            payload_root: payload_root.to_string(),
            payload_bytes,
            public_metadata_root,
            privacy_mode,
            low_fee_lane,
            fee_asset_id: session.preferred_fee_asset_id.clone(),
            max_fee_units: max_fee_units.max(CLIENT_DEFAULT_MAX_FEE_UNITS),
            priority_fee_units: 0,
            idempotency_key_hash,
            rpc_method_name: rpc_method.as_str().to_string(),
            rpc_method,
            workload_intent_id: None,
            workload_intent_root: None,
            crypto_policy_root: crypto_policy_root(),
            authorization: None,
            network_authorization: None,
            network_authority_public_key: None,
            recovery_authorization: None,
            tx_kind,
        })
    }

    pub fn from_workload_intent(
        session: &ClientSession,
        intent: &WorkloadIntent,
        public_metadata: &Value,
    ) -> ClientResult<Self> {
        let tx_kind = ClientTxKind::from_workload_kind(&intent.kind);
        let mut envelope = Self::from_payload_root_with_sequence(
            session,
            intent.sequence,
            tx_kind,
            intent.kind.as_str(),
            &intent.payload_root,
            intent.payload_bytes,
            public_metadata,
            intent.target_height,
            intent.deadline_height,
            CLIENT_DEFAULT_MAX_FEE_UNITS,
        )?;
        envelope.privacy_mode = ClientPrivacyMode::from_workload_class(&intent.privacy_class);
        envelope.low_fee_lane = if intent.low_fee_lane {
            envelope.tx_kind.default_low_fee_lane()
        } else {
            None
        };
        envelope.workload_intent_id = Some(intent.intent_id.clone());
        envelope.workload_intent_root = Some(intent.intent_root());
        Ok(envelope)
    }

    pub fn private_transfer(
        session: &ClientSession,
        payload: &Value,
        public_metadata: &Value,
        target_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        Self::from_payload(
            session,
            ClientTxKind::PrivateTransfer,
            "private_transfer_payload",
            payload,
            public_metadata,
            target_height,
            target_height.saturating_add(CLIENT_DEFAULT_TX_TTL_BLOCKS),
            max_fee_units,
        )
    }

    pub fn defi_call(
        session: &ClientSession,
        payload: &Value,
        public_metadata: &Value,
        target_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        Self::from_payload(
            session,
            ClientTxKind::DefiCall,
            "defi_call_payload",
            payload,
            public_metadata,
            target_height,
            target_height.saturating_add(CLIENT_DEFAULT_TX_TTL_BLOCKS),
            max_fee_units,
        )
    }

    pub fn contract_call(
        session: &ClientSession,
        payload: &Value,
        public_metadata: &Value,
        target_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        Self::from_payload(
            session,
            ClientTxKind::ContractCall,
            "contract_call_payload",
            payload,
            public_metadata,
            target_height,
            target_height.saturating_add(CLIENT_DEFAULT_TX_TTL_BLOCKS),
            max_fee_units,
        )
    }

    pub fn wasm_call(
        session: &ClientSession,
        payload: &Value,
        public_metadata: &Value,
        target_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        Self::from_payload(
            session,
            ClientTxKind::WasmCall,
            "wasm_call_payload",
            payload,
            public_metadata,
            target_height,
            target_height.saturating_add(CLIENT_DEFAULT_TX_TTL_BLOCKS),
            max_fee_units,
        )
    }

    pub fn monero_bridge_action(
        session: &ClientSession,
        payload: &Value,
        public_metadata: &Value,
        target_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        Self::from_payload(
            session,
            ClientTxKind::MoneroBridgeAction,
            "monero_bridge_payload",
            payload,
            public_metadata,
            target_height,
            target_height.saturating_add(CLIENT_DEFAULT_TX_TTL_BLOCKS),
            max_fee_units,
        )
    }

    pub fn from_rpc_request(
        session: &ClientSession,
        request: &RpcRequest,
        target_height: u64,
        max_fee_units: u64,
    ) -> ClientResult<Self> {
        let metadata = json!({
            "rpc_request_id": request.request_id,
            "rpc_method": request.method_name,
        });
        let mut envelope = Self::from_payload_root(
            session,
            ClientTxKind::RpcSubmission,
            "rpc_request",
            &request.root(),
            json_size(&request.public_record()) as u64,
            &metadata,
            target_height,
            request.expires_at_height,
            max_fee_units,
        )?;
        envelope.rpc_method = request.method.clone();
        envelope.rpc_method_name = request.method_name.clone();
        Ok(envelope)
    }

    pub fn signed_by_account(mut self, signer_label: &str) -> Self {
        self.authorization = Some(sign_authorization(
            signer_label,
            CLIENT_ACCOUNT_AUTH_DOMAIN,
            &self.unsigned_record(),
        ));
        self.status = ClientIntentStatus::Signed;
        self
    }

    pub fn signed_by_network(mut self, operator_label: &str) -> Self {
        let authorization = sign_network_authorization(
            operator_label,
            CLIENT_NETWORK_AUTH_DOMAIN,
            &self.unsigned_record(),
        );
        self.network_authority_public_key = Some(authorization.auth_public_key.clone());
        self.network_authorization = Some(authorization);
        self
    }

    pub fn signed_for_recovery(mut self, recovery_label: &str) -> Self {
        self.recovery_authorization = Some(sign_recovery_authorization(
            recovery_label,
            CLIENT_RECOVERY_AUTH_DOMAIN,
            &self.unsigned_record(),
        ));
        self
    }

    pub fn with_priority_fee_units(mut self, priority_fee_units: u64) -> Self {
        self.priority_fee_units = priority_fee_units;
        self
    }

    pub fn with_fee_asset(mut self, fee_asset_id: impl Into<String>) -> Self {
        self.fee_asset_id = fee_asset_id.into();
        self
    }

    pub fn with_low_fee_lane(mut self, lane: Option<LowFeeLane>) -> Self {
        self.low_fee_lane = lane;
        self
    }

    pub fn mark_status(mut self, status: ClientIntentStatus) -> Self {
        self.status = status;
        self
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "client_tx_envelope",
            "chain_id": self.chain_id,
            "client_protocol_version": self.client_protocol_version,
            "tx_id": self.tx_id,
            "tx_kind": self.tx_kind_name,
            "session_id": self.session_id,
            "account_id": self.account_id,
            "account_commitment": self.account_commitment,
            "account_public_key": self.account_public_key,
            "recovery_public_key": self.recovery_public_key,
            "sequence": self.sequence,
            "target_height": self.target_height,
            "deadline_height": self.deadline_height,
            "payload_kind": self.payload_kind,
            "payload_root": self.payload_root,
            "payload_bytes": self.payload_bytes,
            "public_metadata_root": self.public_metadata_root,
            "privacy_mode": self.privacy_mode.as_str(),
            "low_fee_lane": self.low_fee_lane.as_ref().map(LowFeeLane::public_record),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "priority_fee_units": self.priority_fee_units,
            "idempotency_key_hash": self.idempotency_key_hash,
            "rpc_method": self.rpc_method_name,
            "workload_intent_id": self.workload_intent_id,
            "workload_intent_root": self.workload_intent_root,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("client tx envelope record object");
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "unsigned_root".to_string(),
            Value::String(self.unsigned_root()),
        );
        object.insert(
            "authorization_root".to_string(),
            Value::String(self.authorization_root()),
        );
        if let Some(authorization) = &self.authorization {
            insert_authorization_fields(object, authorization);
        }
        if let Some(authorization) = &self.network_authorization {
            insert_prefixed_authorization_fields(object, "network", authorization);
            object.insert(
                "network_authority_public_key".to_string(),
                json!(self.network_authority_public_key),
            );
        }
        if let Some(authorization) = &self.recovery_authorization {
            insert_recovery_authorization_fields(object, authorization);
        }
        record
    }

    pub fn unsigned_root(&self) -> String {
        domain_hash(
            "CLIENT-TX-UNSIGNED",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn root(&self) -> String {
        domain_hash(
            "CLIENT-TX-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn authorization_root(&self) -> String {
        let mut records = Vec::new();
        if let Some(authorization) = &self.authorization {
            records.push(authorization_record("account", authorization));
        }
        if let Some(authorization) = &self.network_authorization {
            records.push(authorization_record("network", authorization));
        }
        if let Some(authorization) = &self.recovery_authorization {
            records.push(recovery_authorization_record(authorization));
        }
        merkle_root("CLIENT-AUTHORIZATION", &records)
    }

    pub fn verify_account_authorization(&self) -> bool {
        self.authorization.as_ref().is_some_and(|authorization| {
            authorization.auth_public_key == self.account_public_key
                && verify_authorization(
                    &authorization.signer_label,
                    CLIENT_ACCOUNT_AUTH_DOMAIN,
                    &self.unsigned_record(),
                    authorization,
                )
        })
    }

    pub fn verify_network_authorization(&self) -> bool {
        match (
            &self.network_authorization,
            &self.network_authority_public_key,
        ) {
            (Some(authorization), Some(public_key)) => verify_network_authorization(
                public_key,
                CLIENT_NETWORK_AUTH_DOMAIN,
                &self.unsigned_record(),
                authorization,
            ),
            _ => false,
        }
    }

    pub fn verify_recovery_authorization(&self) -> bool {
        self.recovery_authorization
            .as_ref()
            .is_some_and(|authorization| {
                authorization.recovery_public_key == self.recovery_public_key
                    && verify_recovery_authorization(
                        &authorization.recovery_label,
                        CLIENT_RECOVERY_AUTH_DOMAIN,
                        &self.unsigned_record(),
                        authorization,
                    )
            })
    }

    pub fn fee_market_resource(&self) -> FeeMarketResource {
        let mut fee_lanes = vec![("operation".to_string(), self.tx_kind_name.clone())];
        if let Some(lane) = &self.low_fee_lane {
            let lane_pair = (lane.lane_type.clone(), lane.lane_key.clone());
            if !fee_lanes.contains(&lane_pair) {
                fee_lanes.push(lane_pair);
            }
        }
        if !self.fee_asset_id.is_empty() {
            fee_lanes.push(("asset".to_string(), self.fee_asset_id.clone()));
        }
        if self.tx_kind.requires_bridge_attestation() {
            fee_lanes.push(("bridge".to_string(), "monero".to_string()));
        }
        if self.tx_kind.contract_call_count() > 0 {
            fee_lanes.push(("execution".to_string(), self.tx_kind_name.clone()));
        }
        let privacy_proof_count =
            u64::from(self.tx_kind.requires_privacy_proof(&self.privacy_mode));
        let bridge_bytes = if self.tx_kind.requires_bridge_attestation() {
            DEVNET_BRIDGE_ATTESTATION_BYTES
        } else {
            0
        };
        let authorization_count = 1
            + u64::from(self.network_authorization.is_some())
            + u64::from(self.recovery_authorization.is_some());
        FeeMarketResource {
            public_record: self.public_record(),
            execution_fuel: self.execution_fuel_estimate(),
            privacy_proof_count,
            contract_call_count: self.tx_kind.contract_call_count(),
            observed_fee_units: self.max_fee_units.saturating_add(self.priority_fee_units),
            estimated_proof_bytes: privacy_proof_count * DEVNET_PRIVACY_PROOF_BYTES + bridge_bytes,
            authorization_count,
            fee_asset_ids: if self.fee_asset_id.is_empty() {
                Vec::new()
            } else {
                vec![self.fee_asset_id.clone()]
            },
            fee_lanes,
        }
    }

    pub fn to_rpc_request(&self, received_at_height: u64, ttl_blocks: u64) -> RpcRequest {
        let payload = self.public_record();
        RpcRequest::from_payload_with_id(
            Some(Value::String(self.tx_id.clone())),
            RpcMethod::SubmitPrivateTx,
            &payload,
            &self.account_commitment,
            &self.tx_id,
            "client_tx_envelope",
            true,
            &json!({
                "client_tx_id": self.tx_id,
                "client_session_id": self.session_id,
                "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            }),
            received_at_height,
            received_at_height.saturating_add(ttl_blocks.max(1)),
            RPC_DEFAULT_MAX_RESPONSE_BYTES,
        )
    }

    fn execution_fuel_estimate(&self) -> u64 {
        match self.tx_kind {
            ClientTxKind::PrivateTransfer => 90,
            ClientTxKind::AssetMint => 90,
            ClientTxKind::AssetBurn => 140,
            ClientTxKind::DefiCall
            | ClientTxKind::AmmSwap
            | ClientTxKind::AmmLiquidityAdd
            | ClientTxKind::LendingBorrow
            | ClientTxKind::LendingRepay => 420,
            ClientTxKind::ContractCall => 520,
            ClientTxKind::WasmCall => 640,
            ClientTxKind::PaymasterSponsoredCall => 560,
            ClientTxKind::MoneroBridgeDeposit
            | ClientTxKind::MoneroBridgeWithdrawal
            | ClientTxKind::MoneroBridgeAction => 180,
            ClientTxKind::OracleUpdate => 80,
            ClientTxKind::ProofJob => 60,
            ClientTxKind::FeeQuote => 20,
            ClientTxKind::RpcSubmission => 40,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientTxReceipt {
    pub receipt_id: String,
    pub tx_id: String,
    pub session_id: String,
    pub batch_id: Option<String>,
    pub status: ClientIntentStatus,
    pub envelope_root: String,
    pub receipt_payload_root: String,
    pub rpc_request_id: Option<String>,
    pub rpc_response_id: Option<String>,
    pub included_height: Option<u64>,
    pub finalized_height: Option<u64>,
    pub fee_charged_units: u64,
    pub rebate_units: u64,
    pub settled_fee_units: u64,
    pub public_metadata_root: String,
    pub recorded_at_height: u64,
    pub expires_at_height: u64,
}

impl ClientTxReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope: &ClientTxEnvelope,
        batch_id: Option<String>,
        status: ClientIntentStatus,
        receipt_payload: &Value,
        recorded_at_height: u64,
        public_metadata: &Value,
    ) -> Self {
        let receipt_payload_root = client_receipt_payload_root(receipt_payload);
        let public_metadata_root = client_public_metadata_root(public_metadata);
        let envelope_root = envelope.root();
        let receipt_id = client_receipt_id(
            &envelope.tx_id,
            batch_id.as_deref(),
            status.as_str(),
            &envelope_root,
            &receipt_payload_root,
            recorded_at_height,
        );
        let fee_charged_units = public_metadata
            .get("fee_charged_units")
            .and_then(Value::as_u64)
            .unwrap_or(envelope.max_fee_units);
        let rebate_units = public_metadata
            .get("rebate_units")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let settled_fee_units = fee_charged_units.saturating_sub(rebate_units);
        Self {
            receipt_id,
            tx_id: envelope.tx_id.clone(),
            session_id: envelope.session_id.clone(),
            batch_id,
            status,
            envelope_root,
            receipt_payload_root,
            rpc_request_id: None,
            rpc_response_id: None,
            included_height: None,
            finalized_height: None,
            fee_charged_units,
            rebate_units,
            settled_fee_units,
            public_metadata_root,
            recorded_at_height,
            expires_at_height: recorded_at_height.saturating_add(CLIENT_DEFAULT_RECEIPT_TTL_BLOCKS),
        }
    }

    pub fn from_rpc_receipt(
        envelope: &ClientTxEnvelope,
        rpc_receipt: &RpcReceipt,
        status: ClientIntentStatus,
        recorded_at_height: u64,
    ) -> Self {
        let payload = rpc_receipt.public_record();
        let metadata = json!({
            "rpc_request_id": rpc_receipt.request_id,
            "rpc_response_id": rpc_receipt.response_id,
            "rpc_status_code": rpc_receipt.status_code,
            "rpc_success": rpc_receipt.success,
        });
        let mut receipt = Self::new(
            envelope,
            None,
            status,
            &payload,
            recorded_at_height,
            &metadata,
        );
        receipt.rpc_request_id = Some(rpc_receipt.request_id.clone());
        receipt.rpc_response_id = rpc_receipt.response_id.clone();
        receipt.expires_at_height = rpc_receipt.expires_at_height;
        receipt
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "client_tx_receipt",
            "chain_id": CHAIN_ID,
            "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "tx_id": self.tx_id,
            "session_id": self.session_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "envelope_root": self.envelope_root,
            "receipt_payload_root": self.receipt_payload_root,
            "rpc_request_id": self.rpc_request_id,
            "rpc_response_id": self.rpc_response_id,
            "included_height": self.included_height,
            "finalized_height": self.finalized_height,
            "fee_charged_units": self.fee_charged_units,
            "rebate_units": self.rebate_units,
            "settled_fee_units": self.settled_fee_units,
            "public_metadata_root": self.public_metadata_root,
            "recorded_at_height": self.recorded_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "CLIENT-TX-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientFeeQuoteRequest {
    pub quote_request_id: String,
    pub session_id: String,
    pub account_id: String,
    pub tx_id: String,
    pub tx_kind: ClientTxKind,
    pub tx_kind_name: String,
    pub candidate_resource: FeeMarketResource,
    pub pending_resource_root: String,
    pub pending_resource_count: u64,
    pub low_fee_lane: Option<LowFeeLane>,
    pub fee_asset_id: String,
    pub target_inclusion_blocks: u64,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub quote: FeeQuote,
    pub public_metadata_root: String,
}

impl ClientFeeQuoteRequest {
    pub fn from_envelope(
        envelope: &ClientTxEnvelope,
        pending_resources: &[FeeMarketResource],
        requested_at_height: u64,
        public_metadata: &Value,
    ) -> Self {
        let candidate_resource = envelope.fee_market_resource();
        let quote = fee_quote(
            envelope.tx_kind.as_str(),
            pending_resources,
            candidate_resource.clone(),
        );
        let pending_resource_root = fee_market_resource_root(pending_resources);
        let public_metadata_root = client_public_metadata_root(public_metadata);
        let quote_request_id = client_fee_quote_request_id(
            &envelope.tx_id,
            &pending_resource_root,
            &quote.quote_hash,
            requested_at_height,
        );
        Self {
            quote_request_id,
            session_id: envelope.session_id.clone(),
            account_id: envelope.account_id.clone(),
            tx_id: envelope.tx_id.clone(),
            tx_kind: envelope.tx_kind.clone(),
            tx_kind_name: envelope.tx_kind_name.clone(),
            candidate_resource,
            pending_resource_root,
            pending_resource_count: pending_resources.len() as u64,
            low_fee_lane: envelope.low_fee_lane.clone(),
            fee_asset_id: envelope.fee_asset_id.clone(),
            target_inclusion_blocks: quote.target_inclusion_blocks,
            requested_at_height,
            expires_at_height: requested_at_height.saturating_add(CLIENT_DEFAULT_TX_TTL_BLOCKS),
            quote,
            public_metadata_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "client_fee_quote_request",
            "chain_id": CHAIN_ID,
            "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            "quote_request_id": self.quote_request_id,
            "session_id": self.session_id,
            "account_id": self.account_id,
            "tx_id": self.tx_id,
            "tx_kind": self.tx_kind_name,
            "candidate_resource": self.candidate_resource,
            "pending_resource_root": self.pending_resource_root,
            "pending_resource_count": self.pending_resource_count,
            "low_fee_lane": self.low_fee_lane.as_ref().map(LowFeeLane::public_record),
            "fee_asset_id": self.fee_asset_id,
            "target_inclusion_blocks": self.target_inclusion_blocks,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "quote": self.quote.public_record(),
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "CLIENT-FEE-QUOTE-REQUEST",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn to_rpc_request(&self) -> RpcRequest {
        let payload = self.public_record();
        RpcRequest::from_payload_with_id(
            Some(Value::String(self.quote_request_id.clone())),
            RpcMethod::LowFeeQuote,
            &payload,
            &self.account_id,
            &self.quote_request_id,
            "client_fee_quote_request",
            false,
            &json!({
                "client_tx_id": self.tx_id,
                "client_quote_request_id": self.quote_request_id,
                "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            }),
            self.requested_at_height,
            self.expires_at_height,
            RPC_DEFAULT_MAX_RESPONSE_BYTES,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSubmissionBatch {
    pub batch_id: String,
    pub session_id: String,
    pub account_id: String,
    pub batch_sequence: u64,
    pub envelope_root: String,
    pub envelope_count: u64,
    pub envelope_ids: Vec<String>,
    pub low_fee_count: u64,
    pub bridge_count: u64,
    pub total_payload_bytes: u64,
    pub max_fee_units: u64,
    pub public_metadata_root: String,
    pub created_at_height: u64,
    pub submitted_at_height: Option<u64>,
    pub crypto_policy_root: String,
    pub authorization: Option<Authorization>,
    pub network_authorization: Option<Authorization>,
    pub network_authority_public_key: Option<String>,
}

impl ClientSubmissionBatch {
    pub fn new(
        session: &ClientSession,
        batch_sequence: u64,
        envelopes: &[ClientTxEnvelope],
        created_at_height: u64,
        public_metadata: &Value,
    ) -> ClientResult<Self> {
        if envelopes.is_empty() {
            return Err("client submission batch requires at least one envelope".to_string());
        }
        if envelopes.len() > CLIENT_DEFAULT_MAX_BATCH_ENVELOPES {
            return Err(format!(
                "client submission batch has {} envelopes; max is {CLIENT_DEFAULT_MAX_BATCH_ENVELOPES}",
                envelopes.len()
            ));
        }
        if envelopes
            .iter()
            .any(|envelope| envelope.session_id != session.session_id)
        {
            return Err("client submission batch cannot mix sessions".to_string());
        }
        let mut envelopes = envelopes.to_vec();
        envelopes.sort_by(|left, right| left.tx_id.cmp(&right.tx_id));
        let envelope_root = client_envelope_root(&envelopes);
        let envelope_ids = envelopes
            .iter()
            .map(|envelope| envelope.tx_id.clone())
            .collect::<Vec<_>>();
        let public_metadata_root = client_public_metadata_root(public_metadata);
        let batch_id = client_submission_batch_id(
            &session.session_id,
            batch_sequence,
            &envelope_root,
            envelopes.len() as u64,
        );
        Ok(Self {
            batch_id,
            session_id: session.session_id.clone(),
            account_id: session.account_id.clone(),
            batch_sequence,
            envelope_root,
            envelope_count: envelopes.len() as u64,
            envelope_ids,
            low_fee_count: envelopes
                .iter()
                .filter(|envelope| envelope.low_fee_lane.is_some())
                .count() as u64,
            bridge_count: envelopes
                .iter()
                .filter(|envelope| envelope.tx_kind.requires_bridge_attestation())
                .count() as u64,
            total_payload_bytes: envelopes
                .iter()
                .map(|envelope| envelope.payload_bytes)
                .sum(),
            max_fee_units: envelopes
                .iter()
                .map(|envelope| envelope.max_fee_units)
                .fold(0_u64, u64::saturating_add),
            public_metadata_root,
            created_at_height,
            submitted_at_height: None,
            crypto_policy_root: crypto_policy_root(),
            authorization: None,
            network_authorization: None,
            network_authority_public_key: None,
        })
    }

    pub fn signed_by_account(mut self, signer_label: &str) -> Self {
        self.authorization = Some(sign_authorization(
            signer_label,
            CLIENT_BATCH_AUTH_DOMAIN,
            &self.unsigned_record(),
        ));
        self
    }

    pub fn signed_by_network(mut self, operator_label: &str) -> Self {
        let authorization = sign_network_authorization(
            operator_label,
            CLIENT_NETWORK_AUTH_DOMAIN,
            &self.unsigned_record(),
        );
        self.network_authority_public_key = Some(authorization.auth_public_key.clone());
        self.network_authorization = Some(authorization);
        self
    }

    pub fn mark_submitted(mut self, submitted_at_height: u64) -> Self {
        self.submitted_at_height = Some(submitted_at_height);
        self
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "client_submission_batch",
            "chain_id": CHAIN_ID,
            "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "session_id": self.session_id,
            "account_id": self.account_id,
            "batch_sequence": self.batch_sequence,
            "envelope_root": self.envelope_root,
            "envelope_count": self.envelope_count,
            "envelope_ids": self.envelope_ids,
            "low_fee_count": self.low_fee_count,
            "bridge_count": self.bridge_count,
            "total_payload_bytes": self.total_payload_bytes,
            "max_fee_units": self.max_fee_units,
            "public_metadata_root": self.public_metadata_root,
            "created_at_height": self.created_at_height,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("client submission batch record object");
        object.insert(
            "submitted_at_height".to_string(),
            json!(self.submitted_at_height),
        );
        object.insert(
            "unsigned_root".to_string(),
            Value::String(self.unsigned_root()),
        );
        if let Some(authorization) = &self.authorization {
            insert_authorization_fields(object, authorization);
        }
        if let Some(authorization) = &self.network_authorization {
            insert_prefixed_authorization_fields(object, "network", authorization);
            object.insert(
                "network_authority_public_key".to_string(),
                json!(self.network_authority_public_key),
            );
        }
        record
    }

    pub fn unsigned_root(&self) -> String {
        domain_hash(
            "CLIENT-SUBMISSION-BATCH-UNSIGNED",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn root(&self) -> String {
        domain_hash(
            "CLIENT-SUBMISSION-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn to_rpc_request(&self, received_at_height: u64) -> RpcRequest {
        let payload = self.public_record();
        RpcRequest::from_payload_with_id(
            Some(Value::String(self.batch_id.clone())),
            RpcMethod::SubmitPrivateTx,
            &payload,
            &self.account_id,
            &self.batch_id,
            "client_submission_batch",
            true,
            &json!({
                "client_batch_id": self.batch_id,
                "client_session_id": self.session_id,
                "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            }),
            received_at_height,
            received_at_height.saturating_add(RPC_DEFAULT_RECEIPT_TTL_BLOCKS),
            RPC_DEFAULT_MAX_RESPONSE_BYTES,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    pub height: u64,
    pub accounts: BTreeMap<String, ClientAccountProfile>,
    pub sessions: BTreeMap<String, ClientSession>,
    pub pending_envelopes: BTreeMap<String, ClientTxEnvelope>,
    pub receipts: BTreeMap<String, ClientTxReceipt>,
    pub batches: BTreeMap<String, ClientSubmissionBatch>,
    pub next_batch_sequence: u64,
    pub crypto_policy_root: String,
}

impl ClientState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            accounts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            pending_envelopes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            next_batch_sequence: 0,
            crypto_policy_root: crypto_policy_root(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn open_session(
        &mut self,
        account_label: &str,
        privacy_mode: ClientPrivacyMode,
        session_nonce: &str,
        ttl_blocks: u64,
        preferred_fee_asset_id: &str,
    ) -> ClientResult<ClientSession> {
        if session_nonce.is_empty() {
            return Err("client session nonce cannot be empty".to_string());
        }
        let profile = ClientAccountProfile::new(
            account_label,
            privacy_mode,
            preferred_fee_asset_id.to_string(),
        );
        let session = ClientSession::new(
            &profile,
            session_nonce,
            self.height,
            ttl_blocks.max(CLIENT_DEFAULT_SESSION_TTL_BLOCKS),
        )
        .signed_by_account();
        self.accounts.insert(profile.account_id.clone(), profile);
        self.sessions
            .insert(session.session_id.clone(), session.clone());
        Ok(session)
    }

    pub fn build_envelope_from_workload(
        &mut self,
        session_id: &str,
        intent: &WorkloadIntent,
        public_metadata: &Value,
    ) -> ClientResult<ClientTxEnvelope> {
        let session = self.live_session(session_id)?.clone();
        let envelope = ClientTxEnvelope::from_workload_intent(&session, intent, public_metadata)?
            .signed_by_account(&session.account_label);
        if !envelope.verify_account_authorization() {
            return Err("client envelope account authorization failed".to_string());
        }
        self.sessions
            .get_mut(session_id)
            .expect("session checked live")
            .observe_sequence(intent.sequence);
        self.pending_envelopes
            .insert(envelope.tx_id.clone(), envelope.clone());
        Ok(envelope)
    }

    pub fn build_fee_quote_request(
        &self,
        session_id: &str,
        envelope: &ClientTxEnvelope,
    ) -> ClientResult<ClientFeeQuoteRequest> {
        self.live_session(session_id)?;
        if envelope.session_id != session_id {
            return Err("fee quote envelope does not belong to session".to_string());
        }
        let pending_resources = self
            .pending_envelopes
            .values()
            .filter(|pending| pending.tx_id != envelope.tx_id)
            .map(ClientTxEnvelope::fee_market_resource)
            .collect::<Vec<_>>();
        Ok(ClientFeeQuoteRequest::from_envelope(
            envelope,
            &pending_resources,
            self.height,
            &json!({ "request_source": "client_state" }),
        ))
    }

    pub fn record_receipt(&mut self, receipt: ClientTxReceipt) -> ClientResult<String> {
        if receipt.recorded_at_height > self.height {
            self.height = receipt.recorded_at_height;
        }
        if let Some(envelope) = self.pending_envelopes.get_mut(&receipt.tx_id) {
            envelope.status = receipt.status.clone();
        }
        if receipt.status.is_terminal() {
            self.pending_envelopes.remove(&receipt.tx_id);
        }
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn batch_envelopes(
        &mut self,
        session_id: &str,
        tx_ids: &[String],
        public_metadata: &Value,
    ) -> ClientResult<ClientSubmissionBatch> {
        let session = self.live_session(session_id)?.clone();
        let mut envelopes = Vec::with_capacity(tx_ids.len());
        for tx_id in tx_ids {
            let envelope = self
                .pending_envelopes
                .get(tx_id)
                .ok_or_else(|| format!("pending envelope not found: {tx_id}"))?;
            if envelope.session_id != session_id {
                return Err(format!(
                    "pending envelope belongs to another session: {tx_id}"
                ));
            }
            envelopes.push(envelope.clone());
        }
        let batch_sequence = self.next_batch_sequence;
        self.next_batch_sequence = self.next_batch_sequence.saturating_add(1);
        let batch = ClientSubmissionBatch::new(
            &session,
            batch_sequence,
            &envelopes,
            self.height,
            public_metadata,
        )?
        .signed_by_account(&session.account_label)
        .mark_submitted(self.height);
        for tx_id in &batch.envelope_ids {
            if let Some(envelope) = self.pending_envelopes.get_mut(tx_id) {
                envelope.status = ClientIntentStatus::Submitted;
            }
        }
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn pending_root(&self) -> String {
        client_envelope_root(
            &self
                .pending_envelopes
                .values()
                .cloned()
                .collect::<Vec<ClientTxEnvelope>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        client_receipt_root(
            &self
                .receipts
                .values()
                .cloned()
                .collect::<Vec<ClientTxReceipt>>(),
        )
    }

    pub fn batch_root(&self) -> String {
        let mut batches = self.batches.values().cloned().collect::<Vec<_>>();
        batches.sort_by(|left, right| left.batch_id.cmp(&right.batch_id));
        merkle_root(
            "CLIENT-SUBMISSION-BATCH",
            &batches
                .iter()
                .map(ClientSubmissionBatch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn account_root(&self) -> String {
        let mut accounts = self.accounts.values().cloned().collect::<Vec<_>>();
        accounts.sort_by(|left, right| left.account_id.cmp(&right.account_id));
        merkle_root(
            "CLIENT-ACCOUNT",
            &accounts
                .iter()
                .map(ClientAccountProfile::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn session_root(&self) -> String {
        let mut sessions = self.sessions.values().cloned().collect::<Vec<_>>();
        sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        merkle_root(
            "CLIENT-SESSION",
            &sessions
                .iter()
                .map(ClientSession::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CLIENT-STATE",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("client state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn live_session(&self, session_id: &str) -> ClientResult<&ClientSession> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("client session not found: {session_id}"))?;
        if !session.is_live(self.height) {
            return Err(format!(
                "client session is not live at height {}",
                self.height
            ));
        }
        Ok(session)
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "client_state",
            "chain_id": CHAIN_ID,
            "client_protocol_version": CLIENT_PROTOCOL_VERSION,
            "height": self.height,
            "account_root": self.account_root(),
            "session_root": self.session_root(),
            "pending_root": self.pending_root(),
            "receipt_root": self.receipt_root(),
            "batch_root": self.batch_root(),
            "account_count": self.accounts.len() as u64,
            "session_count": self.sessions.len() as u64,
            "pending_count": self.pending_envelopes.len() as u64,
            "receipt_count": self.receipts.len() as u64,
            "batch_count": self.batches.len() as u64,
            "next_batch_sequence": self.next_batch_sequence,
            "target_block_ms": TARGET_BLOCK_MS,
            "devnet_auth_bytes": DEVNET_AUTH_BYTES,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }
}

impl Default for ClientState {
    fn default() -> Self {
        Self::new(0)
    }
}

pub fn client_account_id(account_label: &str) -> String {
    domain_hash(
        "CLIENT-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_label),
            HashPart::Str(&crypto_policy_root()),
        ],
        32,
    )
}

pub fn client_session_id(account_id: &str, session_nonce: &str, opened_at_height: u64) -> String {
    domain_hash(
        "CLIENT-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CLIENT_PROTOCOL_VERSION),
            HashPart::Str(account_id),
            HashPart::Str(&client_string_root("CLIENT-SESSION-NONCE", session_nonce)),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn client_tx_id(
    session_id: &str,
    sequence: u64,
    tx_kind: &ClientTxKind,
    payload_root: &str,
    public_metadata_root: &str,
) -> String {
    domain_hash(
        "CLIENT-TX-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CLIENT_PROTOCOL_VERSION),
            HashPart::Str(session_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(tx_kind.as_str()),
            HashPart::Str(payload_root),
            HashPart::Str(public_metadata_root),
        ],
        32,
    )
}

pub fn client_tx_payload_root(tx_kind: &ClientTxKind, payload: &Value) -> String {
    domain_hash(
        "CLIENT-TX-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CLIENT_PROTOCOL_VERSION),
            HashPart::Str(tx_kind.as_str()),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn client_submission_batch_id(
    session_id: &str,
    batch_sequence: u64,
    envelope_root: &str,
    envelope_count: u64,
) -> String {
    domain_hash(
        "CLIENT-SUBMISSION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CLIENT_PROTOCOL_VERSION),
            HashPart::Str(session_id),
            HashPart::Int(batch_sequence as i128),
            HashPart::Str(envelope_root),
            HashPart::Int(envelope_count as i128),
        ],
        32,
    )
}

pub fn client_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn client_envelope_root(envelopes: &[ClientTxEnvelope]) -> String {
    let mut envelopes = envelopes.to_vec();
    envelopes.sort_by(|left, right| left.tx_id.cmp(&right.tx_id));
    merkle_root(
        "CLIENT-TX-ENVELOPE",
        &envelopes
            .iter()
            .map(ClientTxEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn client_receipt_root(receipts: &[ClientTxReceipt]) -> String {
    let mut receipts = receipts.to_vec();
    receipts.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    merkle_root(
        "CLIENT-TX-RECEIPT",
        &receipts
            .iter()
            .map(ClientTxReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_market_resource_root(resources: &[FeeMarketResource]) -> String {
    let mut records = resources
        .iter()
        .map(|resource| {
            let root = domain_hash(
                "CLIENT-FEE-MARKET-RESOURCE",
                &[HashPart::Json(&resource.public_record)],
                32,
            );
            (root, json!(resource))
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "CLIENT-FEE-MARKET-RESOURCE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn client_public_metadata_root(public_metadata: &Value) -> String {
    domain_hash(
        "CLIENT-PUBLIC-METADATA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CLIENT_PROTOCOL_VERSION),
            HashPart::Str(&rpc_public_metadata_root(public_metadata)),
            HashPart::Json(public_metadata),
        ],
        32,
    )
}

fn client_receipt_payload_root(payload: &Value) -> String {
    domain_hash(
        "CLIENT-RECEIPT-PAYLOAD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn client_receipt_id(
    tx_id: &str,
    batch_id: Option<&str>,
    status: &str,
    envelope_root: &str,
    receipt_payload_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "CLIENT-TX-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CLIENT_PROTOCOL_VERSION),
            HashPart::Str(tx_id),
            HashPart::Str(batch_id.unwrap_or("")),
            HashPart::Str(status),
            HashPart::Str(envelope_root),
            HashPart::Str(receipt_payload_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

fn client_fee_quote_request_id(
    tx_id: &str,
    pending_resource_root: &str,
    quote_hash: &str,
    requested_at_height: u64,
) -> String {
    domain_hash(
        "CLIENT-FEE-QUOTE-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CLIENT_PROTOCOL_VERSION),
            HashPart::Str(tx_id),
            HashPart::Str(pending_resource_root),
            HashPart::Str(quote_hash),
            HashPart::Int(requested_at_height as i128),
        ],
        32,
    )
}

fn fee_lane_from_metadata(public_metadata: &Value) -> Option<LowFeeLane> {
    let lane = public_metadata.get("low_fee_lane")?.as_object()?;
    let lane_type = lane.get("lane_type")?.as_str()?;
    let lane_key = lane.get("lane_key")?.as_str()?;
    Some(LowFeeLane::new(lane_type, lane_key))
}

fn privacy_mode_from_metadata(public_metadata: &Value) -> Option<ClientPrivacyMode> {
    match public_metadata.get("privacy_mode")?.as_str()? {
        "public_root_only" => Some(ClientPrivacyMode::PublicRootOnly),
        "metadata_minimized" => Some(ClientPrivacyMode::MetadataMinimized),
        "shielded" => Some(ClientPrivacyMode::Shielded),
        "fully_private" => Some(ClientPrivacyMode::FullyPrivate),
        _ => None,
    }
}

fn authorization_record(kind: &str, authorization: &Authorization) -> Value {
    json!({
        "kind": kind,
        "signer_label_hash": client_string_root("CLIENT-SIGNER-LABEL", &authorization.signer_label),
        "auth_scheme": authorization.auth_scheme,
        "auth_public_key": authorization.auth_public_key,
        "auth_transcript_hash": authorization.auth_transcript_hash,
        "auth_signature": authorization.auth_signature,
    })
}

fn recovery_authorization_record(authorization: &RecoveryAuthorization) -> Value {
    json!({
        "kind": "recovery",
        "recovery_label_hash": client_string_root("CLIENT-RECOVERY-LABEL", &authorization.recovery_label),
        "recovery_scheme": authorization.recovery_scheme,
        "recovery_public_key": authorization.recovery_public_key,
        "recovery_transcript_hash": authorization.recovery_transcript_hash,
        "recovery_signature": authorization.recovery_signature,
    })
}

fn insert_authorization_fields(
    object: &mut serde_json::Map<String, Value>,
    authorization: &Authorization,
) {
    object.insert(
        "auth_scheme".to_string(),
        Value::String(authorization.auth_scheme.clone()),
    );
    object.insert(
        "auth_public_key".to_string(),
        Value::String(authorization.auth_public_key.clone()),
    );
    object.insert(
        "auth_transcript_hash".to_string(),
        Value::String(authorization.auth_transcript_hash.clone()),
    );
    object.insert(
        "auth_signature".to_string(),
        Value::String(authorization.auth_signature.clone()),
    );
}

fn insert_prefixed_authorization_fields(
    object: &mut serde_json::Map<String, Value>,
    prefix: &str,
    authorization: &Authorization,
) {
    object.insert(
        format!("{prefix}_auth_scheme"),
        Value::String(authorization.auth_scheme.clone()),
    );
    object.insert(
        format!("{prefix}_auth_public_key"),
        Value::String(authorization.auth_public_key.clone()),
    );
    object.insert(
        format!("{prefix}_auth_transcript_hash"),
        Value::String(authorization.auth_transcript_hash.clone()),
    );
    object.insert(
        format!("{prefix}_auth_signature"),
        Value::String(authorization.auth_signature.clone()),
    );
}

fn insert_recovery_authorization_fields(
    object: &mut serde_json::Map<String, Value>,
    authorization: &RecoveryAuthorization,
) {
    object.insert(
        "recovery_scheme".to_string(),
        Value::String(authorization.recovery_scheme.clone()),
    );
    object.insert(
        "recovery_public_key".to_string(),
        Value::String(authorization.recovery_public_key.clone()),
    );
    object.insert(
        "recovery_transcript_hash".to_string(),
        Value::String(authorization.recovery_transcript_hash.clone()),
    );
    object.insert(
        "recovery_signature".to_string(),
        Value::String(authorization.recovery_signature.clone()),
    );
}
