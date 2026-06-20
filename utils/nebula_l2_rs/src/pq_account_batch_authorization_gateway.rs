use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqAccountBatchAuthorizationGatewayResult<T> = Result<T, String>;

pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_PROTOCOL_VERSION: &str =
    "nebula-pq-account-batch-authorization-gateway-v1";
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_SCHEMA_VERSION: &str =
    "pq-account-batch-authorization-gateway-state-v1";
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEVNET_LABEL: &str =
    "devnet-pq-account-batch-authorization-gateway";
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_PQ_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s+private-nullifier-set";
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_SESSION_SCHEME: &str =
    "private-session-auth-commitment-v1";
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MAX_BPS: u64 = 10_000;
pub const PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PQ_SECURITY_BITS: u16 = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationLaneKind {
    PrivateTransfer,
    ContractCall,
    DefiSwap,
    Lending,
    Liquidation,
    MoneroBridgeExit,
    ProofAggregation,
    WalletRecovery,
    Automation,
}

impl AuthorizationLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::Liquidation => "liquidation",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
            Self::Automation => "automation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Active,
    Congested,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Congested => "congested",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Active | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    SlhDsaShake192s,
    HybridMlDsaSlhDsa,
}

impl PqAttestationScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake128s => "slh_dsa_shake_128s",
            Self::SlhDsaShake192s => "slh_dsa_shake_192s",
            Self::HybridMlDsaSlhDsa => "hybrid_ml_dsa_slh_dsa",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
            Self::SlhDsaShake128s => 128,
            Self::SlhDsaShake192s => 192,
            Self::HybridMlDsaSlhDsa => 192,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Draft,
    Admitted,
    Sequenced,
    Settled,
    Challenged,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Admitted => "admitted",
            Self::Sequenced => "sequenced",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Draft | Self::Admitted | Self::Sequenced)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountPolicyMode {
    Conservative,
    LowFeeFast,
    PrivateDefi,
    ContractGuarded,
    RecoveryOnly,
    Frozen,
}

impl AccountPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::LowFeeFast => "low_fee_fast",
            Self::PrivateDefi => "private_defi",
            Self::ContractGuarded => "contract_guarded",
            Self::RecoveryOnly => "recovery_only",
            Self::Frozen => "frozen",
        }
    }

    pub fn accepts_lane(self, lane: AuthorizationLaneKind) -> bool {
        match self {
            Self::Conservative => matches!(lane, AuthorizationLaneKind::PrivateTransfer),
            Self::LowFeeFast => !matches!(lane, AuthorizationLaneKind::Liquidation),
            Self::PrivateDefi => matches!(
                lane,
                AuthorizationLaneKind::PrivateTransfer
                    | AuthorizationLaneKind::ContractCall
                    | AuthorizationLaneKind::DefiSwap
                    | AuthorizationLaneKind::Lending
                    | AuthorizationLaneKind::ProofAggregation
            ),
            Self::ContractGuarded => matches!(
                lane,
                AuthorizationLaneKind::ContractCall
                    | AuthorizationLaneKind::ProofAggregation
                    | AuthorizationLaneKind::Automation
            ),
            Self::RecoveryOnly => matches!(lane, AuthorizationLaneKind::WalletRecovery),
            Self::Frozen => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCredentialStatus {
    Offered,
    Active,
    Exhausted,
    Revoked,
    Expired,
    Challenged,
}

impl SponsorCredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Offered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Reserved,
    Included,
    Settled,
    Released,
    Disputed,
    Slashed,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidPqSignature,
    ReplayNullifierReuse,
    SponsorOverspend,
    PolicyBypass,
    DataWithheld,
    BadSettlementRoot,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::ReplayNullifierReuse => "replay_nullifier_reuse",
            Self::SponsorOverspend => "sponsor_overspend",
            Self::PolicyBypass => "policy_bypass",
            Self::DataWithheld => "data_withheld",
            Self::BadSettlementRoot => "bad_settlement_root",
        }
    }
}

pub trait PqAccountBatchAuthorizationGatewayRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub chain_id: String,
    pub pq_suite: String,
    pub commitment_scheme: String,
    pub session_scheme: String,
    pub epoch_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub session_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_lanes: usize,
    pub max_accounts: usize,
    pub max_batches: usize,
    pub max_attestations: usize,
    pub max_sponsor_credentials: usize,
    pub max_nullifiers: usize,
    pub max_receipts: usize,
    pub max_challenges: usize,
    pub max_ops_per_batch: u32,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub require_slh_fallback: bool,
    pub require_private_session_auth: bool,
    pub fee_floor_atomic_units: u64,
}

impl Config {
    pub fn devnet() -> PqAccountBatchAuthorizationGatewayResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_SCHEMA_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            pq_suite: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_PQ_SUITE.to_string(),
            commitment_scheme: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_COMMITMENT_SCHEME.to_string(),
            session_scheme: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_SESSION_SCHEME.to_string(),
            epoch_blocks: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_EPOCH_BLOCKS,
            batch_ttl_blocks: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_BATCH_TTL_BLOCKS,
            session_ttl_blocks: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_SESSION_TTL_BLOCKS,
            challenge_window_blocks:
                PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_lanes: 64,
            max_accounts: 16_384,
            max_batches: 32_768,
            max_attestations: 131_072,
            max_sponsor_credentials: 65_536,
            max_nullifiers: 262_144,
            max_receipts: 65_536,
            max_challenges: 16_384,
            max_ops_per_batch: 4_096,
            min_privacy_set_size: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PQ_SECURITY_BITS,
            max_fee_bps: 75,
            require_slh_fallback: true,
            require_private_session_auth: true,
            fee_floor_atomic_units: 1,
        };
        config.config_id = config_id(&config.protocol_version, &config.schema_version);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.config_id, "config id")?;
        ensure_eq(
            &self.protocol_version,
            PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_PROTOCOL_VERSION,
            "protocol version",
        )?;
        ensure_eq(
            &self.schema_version,
            PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_SCHEMA_VERSION,
            "schema version",
        )?;
        ensure_eq(&self.chain_id, CHAIN_ID, "chain id")?;
        ensure_non_empty(&self.pq_suite, "pq suite")?;
        ensure_non_empty(&self.commitment_scheme, "commitment scheme")?;
        ensure_non_empty(&self.session_scheme, "session scheme")?;
        ensure_positive(self.epoch_blocks, "epoch blocks")?;
        ensure_positive(self.batch_ttl_blocks, "batch ttl blocks")?;
        ensure_positive(self.session_ttl_blocks, "session ttl blocks")?;
        ensure_positive(self.challenge_window_blocks, "challenge window blocks")?;
        ensure_min_capacity(self.max_lanes, "max lanes")?;
        ensure_min_capacity(self.max_accounts, "max accounts")?;
        ensure_min_capacity(self.max_batches, "max batches")?;
        ensure_min_capacity(self.max_attestations, "max attestations")?;
        ensure_min_capacity(self.max_sponsor_credentials, "max sponsor credentials")?;
        ensure_min_capacity(self.max_nullifiers, "max nullifiers")?;
        ensure_min_capacity(self.max_receipts, "max receipts")?;
        ensure_min_capacity(self.max_challenges, "max challenges")?;
        if self.max_ops_per_batch == 0 {
            return Err("max ops per batch must be positive".to_string());
        }
        if self.min_privacy_set_size < PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PRIVACY_SET_SIZE {
            return Err("minimum privacy set size below gateway floor".to_string());
        }
        if self.min_pq_security_bits < PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PQ_SECURITY_BITS {
            return Err("minimum pq security bits below gateway floor".to_string());
        }
        if self.max_fee_bps > PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MAX_BPS {
            return Err("max fee bps exceeds 100 percent".to_string());
        }
        Ok(self.config_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "pq_suite": self.pq_suite,
            "commitment_scheme": self.commitment_scheme,
            "session_scheme": self.session_scheme,
            "epoch_blocks": self.epoch_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "session_ttl_blocks": self.session_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_lanes": self.max_lanes,
            "max_accounts": self.max_accounts,
            "max_batches": self.max_batches,
            "max_attestations": self.max_attestations,
            "max_sponsor_credentials": self.max_sponsor_credentials,
            "max_nullifiers": self.max_nullifiers,
            "max_receipts": self.max_receipts,
            "max_challenges": self.max_challenges,
            "max_ops_per_batch": self.max_ops_per_batch,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "require_slh_fallback": self.require_slh_fallback,
            "require_private_session_auth": self.require_private_session_auth,
            "fee_floor_atomic_units": self.fee_floor_atomic_units,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for Config {
    fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CONFIG",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        Config::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationLane {
    pub lane_id: String,
    pub lane_kind: AuthorizationLaneKind,
    pub status: LaneStatus,
    pub priority: u16,
    pub max_ops_per_batch: u32,
    pub target_fee_bps: u64,
    pub sponsor_allowed: bool,
    pub private_session_required: bool,
    pub policy_root: String,
    pub admission_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl AuthorizationLane {
    pub fn new(
        lane_kind: AuthorizationLaneKind,
        priority: u16,
        max_ops_per_batch: u32,
        target_fee_bps: u64,
        sponsor_allowed: bool,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        let policy_payload = json!({
            "lane_kind": lane_kind.as_str(),
            "sponsor_allowed": sponsor_allowed,
            "private_session_required": true,
        });
        let admission_payload = json!({
            "lane_kind": lane_kind.as_str(),
            "priority": priority,
            "max_ops_per_batch": max_ops_per_batch,
        });
        let mut lane = Self {
            lane_id: String::new(),
            lane_kind,
            status: LaneStatus::Active,
            priority,
            max_ops_per_batch,
            target_fee_bps,
            sponsor_allowed,
            private_session_required: true,
            policy_root: record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-LANE-POLICY", &policy_payload),
            admission_root: record_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-LANE-ADMISSION",
                &admission_payload,
            ),
            opened_at_height: height,
            updated_at_height: height,
        };
        lane.lane_id = lane_id(lane_kind, priority, height);
        lane.validate()?;
        Ok(lane)
    }

    pub fn set_status(
        &mut self,
        status: LaneStatus,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_monotonic(height, self.updated_at_height, "lane status height")?;
        self.status = status;
        self.updated_at_height = height;
        Ok(self.root())
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.lane_id, "lane id")?;
        ensure_non_empty(&self.policy_root, "lane policy root")?;
        ensure_non_empty(&self.admission_root, "lane admission root")?;
        if self.max_ops_per_batch == 0 {
            return Err("lane max ops per batch must be positive".to_string());
        }
        if self.target_fee_bps > PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MAX_BPS {
            return Err("lane target fee bps exceeds 100 percent".to_string());
        }
        ensure_monotonic(
            self.updated_at_height,
            self.opened_at_height,
            "lane updated height",
        )?;
        Ok(self.lane_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "status": self.status.as_str(),
            "priority": self.priority,
            "max_ops_per_batch": self.max_ops_per_batch,
            "target_fee_bps": self.target_fee_bps,
            "sponsor_allowed": self.sponsor_allowed,
            "private_session_required": self.private_session_required,
            "policy_root": self.policy_root,
            "admission_root": self.admission_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for AuthorizationLane {
    fn root(&self) -> String {
        record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-LANE", &self.public_record())
    }

    fn public_record(&self) -> Value {
        AuthorizationLane::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountPolicyCommitment {
    pub account_commitment: String,
    pub policy_id: String,
    pub mode: AccountPolicyMode,
    pub allowed_lanes: BTreeSet<AuthorizationLaneKind>,
    pub spending_limit_commitment: String,
    pub session_key_commitment_root: String,
    pub contract_guard_root: String,
    pub sponsor_policy_root: String,
    pub recovery_root: String,
    pub nonce_domain: String,
    pub privacy_set_size: u64,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
}

impl AccountPolicyCommitment {
    pub fn new(
        account_label: &str,
        mode: AccountPolicyMode,
        allowed_lanes: BTreeSet<AuthorizationLaneKind>,
        privacy_set_size: u64,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        ensure_non_empty(account_label, "account label")?;
        let account_commitment =
            string_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-ACCOUNT", account_label);
        let nonce_domain = string_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-NONCE-DOMAIN", account_label);
        let mut policy = Self {
            account_commitment,
            policy_id: String::new(),
            mode,
            allowed_lanes,
            spending_limit_commitment: string_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPEND-LIMIT",
                account_label,
            ),
            session_key_commitment_root: string_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SESSION-KEYS",
                account_label,
            ),
            contract_guard_root: string_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CONTRACT-GUARD",
                account_label,
            ),
            sponsor_policy_root: string_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPONSOR-POLICY",
                account_label,
            ),
            recovery_root: string_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-RECOVERY", account_label),
            nonce_domain,
            privacy_set_size,
            registered_at_height: height,
            updated_at_height: height,
        };
        policy.policy_id = policy_id(&policy.account_commitment, mode, height);
        policy.validate()?;
        Ok(policy)
    }

    pub fn allows_lane(&self, lane: AuthorizationLaneKind) -> bool {
        self.allowed_lanes.contains(&lane) && self.mode.accepts_lane(lane)
    }

    pub fn update_mode(
        &mut self,
        mode: AccountPolicyMode,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_monotonic(height, self.updated_at_height, "policy update height")?;
        self.mode = mode;
        self.updated_at_height = height;
        self.validate()?;
        Ok(self.root())
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.account_commitment, "account commitment")?;
        ensure_non_empty(&self.policy_id, "policy id")?;
        ensure_non_empty(&self.spending_limit_commitment, "spending limit commitment")?;
        ensure_non_empty(
            &self.session_key_commitment_root,
            "session key commitment root",
        )?;
        ensure_non_empty(&self.contract_guard_root, "contract guard root")?;
        ensure_non_empty(&self.sponsor_policy_root, "sponsor policy root")?;
        ensure_non_empty(&self.recovery_root, "recovery root")?;
        ensure_non_empty(&self.nonce_domain, "nonce domain")?;
        if self.allowed_lanes.is_empty() {
            return Err("account policy must allow at least one lane".to_string());
        }
        if self.privacy_set_size < PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PRIVACY_SET_SIZE {
            return Err("account policy privacy set too small".to_string());
        }
        ensure_monotonic(
            self.updated_at_height,
            self.registered_at_height,
            "policy updated height",
        )?;
        Ok(self.policy_id.clone())
    }

    pub fn public_record(&self) -> Value {
        let allowed_lanes = self
            .allowed_lanes
            .iter()
            .map(|lane| json!(lane.as_str()))
            .collect::<Vec<_>>();
        json!({
            "account_commitment": self.account_commitment,
            "policy_id": self.policy_id,
            "mode": self.mode.as_str(),
            "allowed_lanes": allowed_lanes,
            "spending_limit_commitment": self.spending_limit_commitment,
            "session_key_commitment_root": self.session_key_commitment_root,
            "contract_guard_root": self.contract_guard_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "recovery_root": self.recovery_root,
            "nonce_domain": self.nonce_domain,
            "privacy_set_size": self.privacy_set_size,
            "registered_at_height": self.registered_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for AccountPolicyCommitment {
    fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-ACCOUNT-POLICY",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        AccountPolicyCommitment::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSignatureAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub account_commitment: String,
    pub scheme: PqAttestationScheme,
    pub public_key_commitment: String,
    pub message_root: String,
    pub signature_commitment: String,
    pub witness_root: String,
    pub signer_weight: u64,
    pub verifier_hint: String,
    pub accepted: bool,
    pub created_at_height: u64,
}

impl PqSignatureAttestation {
    pub fn new(
        batch_id: &str,
        account_commitment: &str,
        scheme: PqAttestationScheme,
        message: &Value,
        signer_weight: u64,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        ensure_non_empty(batch_id, "attestation batch id")?;
        ensure_non_empty(account_commitment, "attestation account commitment")?;
        let message_root =
            record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-ATTESTATION-MESSAGE", message);
        let mut attestation = Self {
            attestation_id: String::new(),
            batch_id: batch_id.to_string(),
            account_commitment: account_commitment.to_string(),
            scheme,
            public_key_commitment: record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-PQ-PUBKEY", message),
            message_root,
            signature_commitment: record_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-PQ-SIGNATURE",
                message,
            ),
            witness_root: record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-PQ-WITNESS", message),
            signer_weight,
            verifier_hint: "deterministic-devnet-pq-batch-verifier".to_string(),
            accepted: true,
            created_at_height: height,
        };
        attestation.attestation_id = attestation_id(
            &attestation.batch_id,
            &attestation.account_commitment,
            scheme,
            height,
        );
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.batch_id, "attestation batch id")?;
        ensure_non_empty(&self.account_commitment, "attestation account commitment")?;
        ensure_non_empty(
            &self.public_key_commitment,
            "attestation public key commitment",
        )?;
        ensure_non_empty(&self.message_root, "attestation message root")?;
        ensure_non_empty(
            &self.signature_commitment,
            "attestation signature commitment",
        )?;
        ensure_non_empty(&self.witness_root, "attestation witness root")?;
        ensure_non_empty(&self.verifier_hint, "attestation verifier hint")?;
        if self.scheme.security_bits() < PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PQ_SECURITY_BITS
        {
            return Err("attestation pq security below minimum".to_string());
        }
        if self.signer_weight == 0 {
            return Err("attestation signer weight must be positive".to_string());
        }
        Ok(self.attestation_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "account_commitment": self.account_commitment,
            "scheme": self.scheme.as_str(),
            "public_key_commitment": self.public_key_commitment,
            "message_root": self.message_root,
            "signature_commitment": self.signature_commitment,
            "witness_root": self.witness_root,
            "signer_weight": self.signer_weight,
            "verifier_hint": self.verifier_hint,
            "accepted": self.accepted,
            "created_at_height": self.created_at_height,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for PqSignatureAttestation {
    fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-ATTESTATION",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        PqSignatureAttestation::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorCredential {
    pub credential_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub status: SponsorCredentialStatus,
    pub allowance_atomic_units: u64,
    pub spent_atomic_units: u64,
    pub max_fee_bps: u64,
    pub blind_credential_root: String,
    pub revocation_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorCredential {
    pub fn new(
        sponsor_label: &str,
        lane_id: &str,
        allowance_atomic_units: u64,
        max_fee_bps: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        ensure_non_empty(sponsor_label, "sponsor label")?;
        ensure_non_empty(lane_id, "sponsor credential lane id")?;
        ensure_positive(ttl_blocks, "sponsor credential ttl")?;
        let sponsor_commitment =
            string_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPONSOR", sponsor_label);
        let expires_at_height = issued_at_height.saturating_add(ttl_blocks);
        let mut credential = Self {
            credential_id: String::new(),
            sponsor_commitment,
            lane_id: lane_id.to_string(),
            status: SponsorCredentialStatus::Offered,
            allowance_atomic_units,
            spent_atomic_units: 0,
            max_fee_bps,
            blind_credential_root: string_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BLIND-SPONSOR-CREDENTIAL",
                sponsor_label,
            ),
            revocation_root: string_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPONSOR-REVOCATION",
                sponsor_label,
            ),
            issued_at_height,
            expires_at_height,
        };
        credential.credential_id =
            sponsor_credential_id(&credential.sponsor_commitment, lane_id, issued_at_height);
        credential.validate()?;
        Ok(credential)
    }

    pub fn charge(
        &mut self,
        amount: u64,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_monotonic(height, self.issued_at_height, "sponsor charge height")?;
        if !self.status.spendable() {
            return Err("sponsor credential is not spendable".to_string());
        }
        let next_spent = self.spent_atomic_units.saturating_add(amount);
        if next_spent > self.allowance_atomic_units {
            return Err("sponsor credential allowance exceeded".to_string());
        }
        self.spent_atomic_units = next_spent;
        self.status = if self.spent_atomic_units == self.allowance_atomic_units {
            SponsorCredentialStatus::Exhausted
        } else {
            SponsorCredentialStatus::Active
        };
        Ok(self.root())
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.credential_id, "sponsor credential id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.lane_id, "sponsor credential lane id")?;
        ensure_non_empty(&self.blind_credential_root, "blind credential root")?;
        ensure_non_empty(&self.revocation_root, "sponsor revocation root")?;
        if self.allowance_atomic_units == 0 {
            return Err("sponsor allowance must be positive".to_string());
        }
        if self.spent_atomic_units > self.allowance_atomic_units {
            return Err("sponsor spent amount exceeds allowance".to_string());
        }
        if self.max_fee_bps > PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MAX_BPS {
            return Err("sponsor max fee bps exceeds 100 percent".to_string());
        }
        ensure_monotonic(
            self.expires_at_height,
            self.issued_at_height,
            "sponsor expiry height",
        )?;
        Ok(self.credential_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credential_id": self.credential_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "allowance_atomic_units": self.allowance_atomic_units,
            "spent_atomic_units": self.spent_atomic_units,
            "max_fee_bps": self.max_fee_bps,
            "blind_credential_root": self.blind_credential_root,
            "revocation_root": self.revocation_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for SponsorCredential {
    fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPONSOR-CREDENTIAL",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        SponsorCredential::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayNullifier {
    pub nullifier: String,
    pub batch_id: String,
    pub account_commitment: String,
    pub lane_id: String,
    pub nonce_domain: String,
    pub operation_index: u32,
    pub spent_at_height: u64,
}

impl ReplayNullifier {
    pub fn new(
        batch_id: &str,
        account_commitment: &str,
        lane_id: &str,
        nonce_domain: &str,
        operation_index: u32,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        ensure_non_empty(batch_id, "nullifier batch id")?;
        ensure_non_empty(account_commitment, "nullifier account commitment")?;
        ensure_non_empty(lane_id, "nullifier lane id")?;
        ensure_non_empty(nonce_domain, "nullifier nonce domain")?;
        let nullifier = replay_nullifier(
            batch_id,
            account_commitment,
            lane_id,
            nonce_domain,
            operation_index,
        );
        let record = Self {
            nullifier,
            batch_id: batch_id.to_string(),
            account_commitment: account_commitment.to_string(),
            lane_id: lane_id.to_string(),
            nonce_domain: nonce_domain.to_string(),
            operation_index,
            spent_at_height: height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.nullifier, "replay nullifier")?;
        ensure_non_empty(&self.batch_id, "nullifier batch id")?;
        ensure_non_empty(&self.account_commitment, "nullifier account commitment")?;
        ensure_non_empty(&self.lane_id, "nullifier lane id")?;
        ensure_non_empty(&self.nonce_domain, "nullifier nonce domain")?;
        Ok(self.nullifier.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "batch_id": self.batch_id,
            "account_commitment": self.account_commitment,
            "lane_id": self.lane_id,
            "nonce_domain": self.nonce_domain,
            "operation_index": self.operation_index,
            "spent_at_height": self.spent_at_height,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for ReplayNullifier {
    fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-REPLAY-NULLIFIER",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        ReplayNullifier::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchedAuthorizationEnvelope {
    pub batch_id: String,
    pub lane_id: String,
    pub aggregator_commitment: String,
    pub operation_count: u32,
    pub account_commitment_root: String,
    pub operation_root: String,
    pub session_auth_root: String,
    pub attestation_root: String,
    pub sponsor_credential_root: String,
    pub replay_nullifier_root: String,
    pub policy_route_root: String,
    pub max_fee_atomic_units: u64,
    pub status: BatchStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequenced_at_height: Option<u64>,
}

impl BatchedAuthorizationEnvelope {
    pub fn new(
        lane_id: &str,
        aggregator_label: &str,
        operation_count: u32,
        operation_records: &[Value],
        policy_route_records: &[Value],
        max_fee_atomic_units: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        ensure_non_empty(lane_id, "batch lane id")?;
        ensure_non_empty(aggregator_label, "batch aggregator label")?;
        ensure_positive(ttl_blocks, "batch ttl")?;
        if operation_count == 0 {
            return Err("batch operation count must be positive".to_string());
        }
        let aggregator_commitment =
            string_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-AGGREGATOR", aggregator_label);
        let operation_root = merkle_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-OPERATION",
            operation_records,
        );
        let policy_route_root = merkle_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-POLICY-ROUTE",
            policy_route_records,
        );
        let account_commitment_root = merkle_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-ACCOUNT",
            operation_records,
        );
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let mut envelope = Self {
            batch_id: String::new(),
            lane_id: lane_id.to_string(),
            aggregator_commitment,
            operation_count,
            account_commitment_root,
            operation_root,
            session_auth_root: merkle_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-SESSION-AUTH",
                operation_records,
            ),
            attestation_root: merkle_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-ATTESTATION", &[]),
            sponsor_credential_root: merkle_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-SPONSOR",
                &[],
            ),
            replay_nullifier_root: merkle_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-NULLIFIER",
                &[],
            ),
            policy_route_root,
            max_fee_atomic_units,
            status: BatchStatus::Draft,
            created_at_height,
            expires_at_height,
            sequenced_at_height: None,
        };
        envelope.batch_id = batch_id(
            &envelope.lane_id,
            &envelope.aggregator_commitment,
            &envelope.operation_root,
            created_at_height,
        );
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn attach_roots(
        &mut self,
        attestation_records: &[Value],
        sponsor_records: &[Value],
        nullifier_records: &[Value],
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        self.attestation_root = merkle_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-ATTESTATION",
            attestation_records,
        );
        self.sponsor_credential_root = merkle_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-SPONSOR",
            sponsor_records,
        );
        self.replay_nullifier_root = merkle_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-NULLIFIER",
            nullifier_records,
        );
        self.validate()?;
        Ok(self.root())
    }

    pub fn set_status(
        &mut self,
        status: BatchStatus,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_monotonic(height, self.created_at_height, "batch status height")?;
        if matches!(status, BatchStatus::Sequenced | BatchStatus::Settled) {
            self.sequenced_at_height = Some(height);
        }
        self.status = status;
        self.validate()?;
        Ok(self.root())
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.batch_id, "batch id")?;
        ensure_non_empty(&self.lane_id, "batch lane id")?;
        ensure_non_empty(&self.aggregator_commitment, "batch aggregator commitment")?;
        ensure_non_empty(
            &self.account_commitment_root,
            "batch account commitment root",
        )?;
        ensure_non_empty(&self.operation_root, "batch operation root")?;
        ensure_non_empty(&self.session_auth_root, "batch session auth root")?;
        ensure_non_empty(&self.attestation_root, "batch attestation root")?;
        ensure_non_empty(
            &self.sponsor_credential_root,
            "batch sponsor credential root",
        )?;
        ensure_non_empty(&self.replay_nullifier_root, "batch replay nullifier root")?;
        ensure_non_empty(&self.policy_route_root, "batch policy route root")?;
        if self.operation_count == 0 {
            return Err("batch operation count must be positive".to_string());
        }
        ensure_monotonic(
            self.expires_at_height,
            self.created_at_height,
            "batch expiry height",
        )?;
        if let Some(height) = self.sequenced_at_height {
            ensure_monotonic(height, self.created_at_height, "batch sequenced height")?;
        }
        Ok(self.batch_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "aggregator_commitment": self.aggregator_commitment,
            "operation_count": self.operation_count,
            "account_commitment_root": self.account_commitment_root,
            "operation_root": self.operation_root,
            "session_auth_root": self.session_auth_root,
            "attestation_root": self.attestation_root,
            "sponsor_credential_root": self.sponsor_credential_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "policy_route_root": self.policy_route_root,
            "max_fee_atomic_units": self.max_fee_atomic_units,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequenced_at_height": self.sequenced_at_height,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for BatchedAuthorizationEnvelope {
    fn root(&self) -> String {
        record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH", &self.public_record())
    }

    fn public_record(&self) -> Value {
        BatchedAuthorizationEnvelope::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub status: SettlementReceiptStatus,
    pub settled_operation_count: u32,
    pub fee_charged_atomic_units: u64,
    pub settlement_root: String,
    pub inclusion_root: String,
    pub sponsor_debit_root: String,
    pub emitted_at_height: u64,
}

impl SettlementReceipt {
    pub fn new(
        batch_id: &str,
        lane_id: &str,
        settled_operation_count: u32,
        fee_charged_atomic_units: u64,
        emitted_at_height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        ensure_non_empty(batch_id, "receipt batch id")?;
        ensure_non_empty(lane_id, "receipt lane id")?;
        if settled_operation_count == 0 {
            return Err("receipt settled operation count must be positive".to_string());
        }
        let payload = json!({
            "batch_id": batch_id,
            "lane_id": lane_id,
            "count": settled_operation_count,
            "fee": fee_charged_atomic_units
        });
        let mut receipt = Self {
            receipt_id: String::new(),
            batch_id: batch_id.to_string(),
            lane_id: lane_id.to_string(),
            status: SettlementReceiptStatus::Reserved,
            settled_operation_count,
            fee_charged_atomic_units,
            settlement_root: record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SETTLEMENT", &payload),
            inclusion_root: record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-INCLUSION", &payload),
            sponsor_debit_root: record_root(
                "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPONSOR-DEBIT",
                &payload,
            ),
            emitted_at_height,
        };
        receipt.receipt_id = settlement_receipt_id(batch_id, lane_id, emitted_at_height);
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn set_status(
        &mut self,
        status: SettlementReceiptStatus,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        self.status = status;
        self.validate()?;
        Ok(self.root())
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.receipt_id, "settlement receipt id")?;
        ensure_non_empty(&self.batch_id, "settlement receipt batch id")?;
        ensure_non_empty(&self.lane_id, "settlement receipt lane id")?;
        ensure_non_empty(&self.settlement_root, "settlement root")?;
        ensure_non_empty(&self.inclusion_root, "settlement inclusion root")?;
        ensure_non_empty(&self.sponsor_debit_root, "settlement sponsor debit root")?;
        if self.settled_operation_count == 0 {
            return Err("settled operation count must be positive".to_string());
        }
        Ok(self.receipt_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "settled_operation_count": self.settled_operation_count,
            "fee_charged_atomic_units": self.fee_charged_atomic_units,
            "settlement_root": self.settlement_root,
            "inclusion_root": self.inclusion_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for SettlementReceipt {
    fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub batch_id: String,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub disputed_record_root: String,
    pub slashing_claim_atomic_units: u64,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub upheld: Option<bool>,
}

impl ChallengeEvidence {
    pub fn new(
        batch_id: &str,
        challenger_label: &str,
        kind: ChallengeKind,
        evidence: &Value,
        slashing_claim_atomic_units: u64,
        opened_at_height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        ensure_non_empty(batch_id, "challenge batch id")?;
        ensure_non_empty(challenger_label, "challenge challenger label")?;
        let challenger_commitment =
            string_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CHALLENGER", challenger_label);
        let evidence_root =
            record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CHALLENGE-EVIDENCE", evidence);
        let disputed_record_root =
            record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-DISPUTED-RECORD", evidence);
        let mut challenge = Self {
            challenge_id: String::new(),
            batch_id: batch_id.to_string(),
            challenger_commitment,
            kind,
            evidence_root,
            disputed_record_root,
            slashing_claim_atomic_units,
            opened_at_height,
            resolved_at_height: None,
            upheld: None,
        };
        challenge.challenge_id = challenge_id(
            batch_id,
            &challenge.challenger_commitment,
            kind,
            opened_at_height,
        );
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn resolve(
        &mut self,
        upheld: bool,
        height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_monotonic(height, self.opened_at_height, "challenge resolution height")?;
        self.resolved_at_height = Some(height);
        self.upheld = Some(upheld);
        self.validate()?;
        Ok(self.root())
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.batch_id, "challenge batch id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        ensure_non_empty(&self.disputed_record_root, "challenge disputed record root")?;
        if let Some(height) = self.resolved_at_height {
            ensure_monotonic(height, self.opened_at_height, "challenge resolved height")?;
        }
        Ok(self.challenge_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "challenger_commitment": self.challenger_commitment,
            "kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "disputed_record_root": self.disputed_record_root,
            "slashing_claim_atomic_units": self.slashing_claim_atomic_units,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "upheld": self.upheld,
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for ChallengeEvidence {
    fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CHALLENGE",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        ChallengeEvidence::public_record(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub lanes: usize,
    pub accounts: usize,
    pub batches: usize,
    pub attestations: usize,
    pub sponsor_credentials: usize,
    pub replay_nullifiers: usize,
    pub receipts: usize,
    pub challenges: usize,
    pub open_batches: usize,
    pub challenged_batches: usize,
    pub settled_batches: usize,
    pub sponsored_fee_atomic_units: u64,
    pub slashing_claim_atomic_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "accounts": self.accounts,
            "batches": self.batches,
            "attestations": self.attestations,
            "sponsor_credentials": self.sponsor_credentials,
            "replay_nullifiers": self.replay_nullifiers,
            "receipts": self.receipts,
            "challenges": self.challenges,
            "open_batches": self.open_batches,
            "challenged_batches": self.challenged_batches,
            "settled_batches": self.settled_batches,
            "sponsored_fee_atomic_units": self.sponsored_fee_atomic_units,
            "slashing_claim_atomic_units": self.slashing_claim_atomic_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub account_policy_root: String,
    pub batch_root: String,
    pub attestation_root: String,
    pub sponsor_credential_root: String,
    pub replay_nullifier_root: String,
    pub settlement_receipt_root: String,
    pub challenge_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "account_policy_root": self.account_policy_root,
            "batch_root": self.batch_root,
            "attestation_root": self.attestation_root,
            "sponsor_credential_root": self.sponsor_credential_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "challenge_root": self.challenge_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub lanes: BTreeMap<String, AuthorizationLane>,
    pub account_policies: BTreeMap<String, AccountPolicyCommitment>,
    pub batches: BTreeMap<String, BatchedAuthorizationEnvelope>,
    pub attestations: BTreeMap<String, PqSignatureAttestation>,
    pub sponsor_credentials: BTreeMap<String, SponsorCredential>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    pub nullifier_index: BTreeSet<String>,
    pub account_batch_index: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> PqAccountBatchAuthorizationGatewayResult<Self> {
        let config = Config::devnet()?;
        let mut state = Self {
            config,
            height: 1,
            epoch: 0,
            lanes: BTreeMap::new(),
            account_policies: BTreeMap::new(),
            batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_credentials: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            account_batch_index: BTreeMap::new(),
        };
        for (kind, priority, fee_bps, sponsor) in [
            (AuthorizationLaneKind::PrivateTransfer, 10, 8, true),
            (AuthorizationLaneKind::ContractCall, 20, 15, true),
            (AuthorizationLaneKind::DefiSwap, 30, 20, true),
            (AuthorizationLaneKind::MoneroBridgeExit, 40, 12, true),
            (AuthorizationLaneKind::WalletRecovery, 50, 5, false),
            (AuthorizationLaneKind::ProofAggregation, 60, 4, true),
        ] {
            let lane =
                AuthorizationLane::new(kind, priority, 2_048, fee_bps, sponsor, state.height)?;
            state.add_lane(lane)?;
        }
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(
        &mut self,
        new_height: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<u64> {
        ensure_monotonic(new_height, self.height, "state height")?;
        self.height = new_height;
        self.epoch = new_height / self.config.epoch_blocks;
        Ok(self.height)
    }

    pub fn set_height(&mut self, new_height: u64) -> PqAccountBatchAuthorizationGatewayResult<u64> {
        self.update_height(new_height)
    }

    pub fn add_lane(
        &mut self,
        lane: AuthorizationLane,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        lane.validate()?;
        ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        ensure_absent(
            self.lanes.contains_key(&lane.lane_id),
            "lane already exists",
        )?;
        let id = lane.lane_id.clone();
        self.lanes.insert(id.clone(), lane);
        Ok(id)
    }

    pub fn register_account_policy(
        &mut self,
        policy: AccountPolicyCommitment,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        policy.validate()?;
        ensure_capacity(
            self.account_policies.len(),
            self.config.max_accounts,
            "account policies",
        )?;
        ensure_absent(
            self.account_policies
                .contains_key(&policy.account_commitment),
            "account policy already exists",
        )?;
        let id = policy.account_commitment.clone();
        self.account_policies.insert(id.clone(), policy);
        Ok(id)
    }

    pub fn submit_batch(
        &mut self,
        mut batch: BatchedAuthorizationEnvelope,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        batch.validate()?;
        ensure_capacity(self.batches.len(), self.config.max_batches, "batches")?;
        ensure_absent(
            self.batches.contains_key(&batch.batch_id),
            "batch already exists",
        )?;
        let lane = self
            .lanes
            .get(&batch.lane_id)
            .ok_or_else(|| "batch lane is unknown".to_string())?;
        if !lane.status.accepts_batches() {
            return Err("batch lane is not accepting batches".to_string());
        }
        if batch.operation_count > lane.max_ops_per_batch
            || batch.operation_count > self.config.max_ops_per_batch
        {
            return Err("batch operation count exceeds lane or config capacity".to_string());
        }
        ensure_monotonic(
            batch.expires_at_height,
            self.height,
            "batch expiry against state height",
        )?;
        batch.status = BatchStatus::Admitted;
        let id = batch.batch_id.clone();
        self.batches.insert(id.clone(), batch);
        Ok(id)
    }

    pub fn add_attestation(
        &mut self,
        attestation: PqSignatureAttestation,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        attestation.validate()?;
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        ensure_absent(
            self.attestations.contains_key(&attestation.attestation_id),
            "attestation already exists",
        )?;
        if !self.batches.contains_key(&attestation.batch_id) {
            return Err("attestation batch is unknown".to_string());
        }
        let id = attestation.attestation_id.clone();
        self.account_batch_index
            .entry(attestation.account_commitment.clone())
            .or_default()
            .insert(attestation.batch_id.clone());
        self.attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn add_sponsor_credential(
        &mut self,
        credential: SponsorCredential,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        credential.validate()?;
        ensure_capacity(
            self.sponsor_credentials.len(),
            self.config.max_sponsor_credentials,
            "sponsor credentials",
        )?;
        ensure_absent(
            self.sponsor_credentials
                .contains_key(&credential.credential_id),
            "sponsor credential already exists",
        )?;
        if !self.lanes.contains_key(&credential.lane_id) {
            return Err("sponsor credential lane is unknown".to_string());
        }
        let id = credential.credential_id.clone();
        self.sponsor_credentials.insert(id.clone(), credential);
        Ok(id)
    }

    pub fn spend_sponsor_credential(
        &mut self,
        credential_id: &str,
        amount: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        let credential = self
            .sponsor_credentials
            .get_mut(credential_id)
            .ok_or_else(|| "sponsor credential is unknown".to_string())?;
        credential.charge(amount, self.height)
    }

    pub fn record_nullifier(
        &mut self,
        nullifier: ReplayNullifier,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        nullifier.validate()?;
        ensure_capacity(
            self.replay_nullifiers.len(),
            self.config.max_nullifiers,
            "replay nullifiers",
        )?;
        ensure_absent(
            self.nullifier_index.contains(&nullifier.nullifier),
            "replay nullifier already spent",
        )?;
        if !self.batches.contains_key(&nullifier.batch_id) {
            return Err("nullifier batch is unknown".to_string());
        }
        let id = nullifier.nullifier.clone();
        self.nullifier_index.insert(id.clone());
        self.replay_nullifiers.insert(id.clone(), nullifier);
        Ok(id)
    }

    pub fn settle_batch(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        receipt.validate()?;
        ensure_capacity(
            self.settlement_receipts.len(),
            self.config.max_receipts,
            "settlement receipts",
        )?;
        ensure_absent(
            self.settlement_receipts.contains_key(&receipt.receipt_id),
            "settlement receipt already exists",
        )?;
        let batch = self
            .batches
            .get_mut(&receipt.batch_id)
            .ok_or_else(|| "settlement batch is unknown".to_string())?;
        batch.set_status(BatchStatus::Settled, self.height)?;
        let id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn open_challenge(
        &mut self,
        challenge: ChallengeEvidence,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        challenge.validate()?;
        ensure_capacity(
            self.challenges.len(),
            self.config.max_challenges,
            "challenges",
        )?;
        ensure_absent(
            self.challenges.contains_key(&challenge.challenge_id),
            "challenge already exists",
        )?;
        let batch = self
            .batches
            .get_mut(&challenge.batch_id)
            .ok_or_else(|| "challenge batch is unknown".to_string())?;
        batch.set_status(BatchStatus::Challenged, self.height)?;
        let id = challenge.challenge_id.clone();
        self.challenges.insert(id.clone(), challenge);
        Ok(id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        upheld: bool,
    ) -> PqAccountBatchAuthorizationGatewayResult<String> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "challenge is unknown".to_string())?;
        challenge.resolve(upheld, self.height)?;
        if let Some(batch) = self.batches.get_mut(&challenge.batch_id) {
            if upheld {
                batch.set_status(BatchStatus::Rejected, self.height)?;
            } else if batch.status == BatchStatus::Challenged {
                batch.set_status(BatchStatus::Sequenced, self.height)?;
            }
        }
        Ok(challenge.root())
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        self.config.validate()?;
        ensure_eq(&self.config.chain_id, CHAIN_ID, "state chain id")?;
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for policy in self.account_policies.values() {
            policy.validate()?;
        }
        for batch in self.batches.values() {
            batch.validate()?;
            if !self.lanes.contains_key(&batch.lane_id) {
                return Err("state contains batch for unknown lane".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.batches.contains_key(&attestation.batch_id) {
                return Err("state contains attestation for unknown batch".to_string());
            }
        }
        for credential in self.sponsor_credentials.values() {
            credential.validate()?;
            if !self.lanes.contains_key(&credential.lane_id) {
                return Err("state contains sponsor credential for unknown lane".to_string());
            }
        }
        for nullifier in self.replay_nullifiers.values() {
            nullifier.validate()?;
            if !self.nullifier_index.contains(&nullifier.nullifier) {
                return Err("state nullifier index missing replay nullifier".to_string());
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(self.state_root())
    }

    pub fn counters(&self) -> Counters {
        let mut counters = Counters {
            lanes: self.lanes.len(),
            accounts: self.account_policies.len(),
            batches: self.batches.len(),
            attestations: self.attestations.len(),
            sponsor_credentials: self.sponsor_credentials.len(),
            replay_nullifiers: self.replay_nullifiers.len(),
            receipts: self.settlement_receipts.len(),
            challenges: self.challenges.len(),
            open_batches: 0,
            challenged_batches: 0,
            settled_batches: 0,
            sponsored_fee_atomic_units: 0,
            slashing_claim_atomic_units: 0,
        };
        for batch in self.batches.values() {
            if batch.status.open() {
                counters.open_batches += 1;
            }
            if batch.status == BatchStatus::Challenged {
                counters.challenged_batches += 1;
            }
            if batch.status == BatchStatus::Settled {
                counters.settled_batches += 1;
            }
        }
        for credential in self.sponsor_credentials.values() {
            counters.sponsored_fee_atomic_units = counters
                .sponsored_fee_atomic_units
                .saturating_add(credential.spent_atomic_units);
        }
        for challenge in self.challenges.values() {
            counters.slashing_claim_atomic_units = counters
                .slashing_claim_atomic_units
                .saturating_add(challenge.slashing_claim_atomic_units);
        }
        counters
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let lane_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-LANE-SET",
            self.lanes
                .values()
                .map(AuthorizationLane::public_record)
                .collect(),
        );
        let account_policy_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-ACCOUNT-POLICY-SET",
            self.account_policies
                .values()
                .map(AccountPolicyCommitment::public_record)
                .collect(),
        );
        let batch_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-SET",
            self.batches
                .values()
                .map(BatchedAuthorizationEnvelope::public_record)
                .collect(),
        );
        let attestation_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-ATTESTATION-SET",
            self.attestations
                .values()
                .map(PqSignatureAttestation::public_record)
                .collect(),
        );
        let sponsor_credential_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPONSOR-CREDENTIAL-SET",
            self.sponsor_credentials
                .values()
                .map(SponsorCredential::public_record)
                .collect(),
        );
        let replay_nullifier_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-REPLAY-NULLIFIER-SET",
            self.replay_nullifiers
                .values()
                .map(ReplayNullifier::public_record)
                .collect(),
        );
        let settlement_receipt_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SETTLEMENT-RECEIPT-SET",
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        let challenge_root = merkle_from_records(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CHALLENGE-SET",
            self.challenges
                .values()
                .map(ChallengeEvidence::public_record)
                .collect(),
        );
        let counter_record = self.counters().public_record();
        let counter_root = record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-COUNTERS", &counter_record);
        let state_record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "epoch": self.epoch,
            "config_root": config_root,
            "lane_root": lane_root,
            "account_policy_root": account_policy_root,
            "batch_root": batch_root,
            "attestation_root": attestation_root,
            "sponsor_credential_root": sponsor_credential_root,
            "replay_nullifier_root": replay_nullifier_root,
            "settlement_receipt_root": settlement_receipt_root,
            "challenge_root": challenge_root,
            "counter_root": counter_root,
        });
        let state_root = record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-STATE", &state_record);
        Roots {
            config_root,
            lane_root,
            account_policy_root,
            batch_root,
            attestation_root,
            sponsor_credential_root,
            replay_nullifier_root,
            settlement_receipt_root,
            challenge_root,
            counter_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }
}

impl PqAccountBatchAuthorizationGatewayRooted for State {
    fn root(&self) -> String {
        self.state_root()
    }

    fn public_record(&self) -> Value {
        State::public_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRouteTemplate {
    pub route_id: String,
    pub lane_kind: AuthorizationLaneKind,
    pub mode: AccountPolicyMode,
    pub min_attestations: u16,
    pub sponsor_allowed: bool,
    pub privacy_set_size: u64,
    pub route_root: String,
}

impl PolicyRouteTemplate {
    pub fn new(
        lane_kind: AuthorizationLaneKind,
        mode: AccountPolicyMode,
        min_attestations: u16,
        sponsor_allowed: bool,
        privacy_set_size: u64,
    ) -> PqAccountBatchAuthorizationGatewayResult<Self> {
        if min_attestations == 0 {
            return Err("policy route template min attestations must be positive".to_string());
        }
        if privacy_set_size < PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PRIVACY_SET_SIZE {
            return Err("policy route template privacy set too small".to_string());
        }
        let seed = json!({
            "lane_kind": lane_kind.as_str(),
            "mode": mode.as_str(),
            "min_attestations": min_attestations,
            "sponsor_allowed": sponsor_allowed,
            "privacy_set_size": privacy_set_size
        });
        let route_root = record_root("PQ-ACCOUNT-BATCH-AUTH-GATEWAY-POLICY-ROUTE-TEMPLATE", &seed);
        let route_id = domain_hash(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-POLICY-ROUTE-TEMPLATE-ID",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&seed)],
            32,
        );
        Ok(Self {
            route_id,
            lane_kind,
            mode,
            min_attestations,
            sponsor_allowed,
            privacy_set_size,
            route_root,
        })
    }

    pub fn validate(&self) -> PqAccountBatchAuthorizationGatewayResult<String> {
        ensure_non_empty(&self.route_id, "policy route template id")?;
        ensure_non_empty(&self.route_root, "policy route template root")?;
        if self.min_attestations == 0 {
            return Err("policy route template min attestations must be positive".to_string());
        }
        if self.privacy_set_size < PQ_ACCOUNT_BATCH_AUTHORIZATION_GATEWAY_MIN_PRIVACY_SET_SIZE {
            return Err("policy route template privacy set too small".to_string());
        }
        Ok(self.route_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "lane_kind": self.lane_kind.as_str(),
            "mode": self.mode.as_str(),
            "min_attestations": self.min_attestations,
            "sponsor_allowed": self.sponsor_allowed,
            "privacy_set_size": self.privacy_set_size,
            "route_root": self.route_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-POLICY-ROUTE-TEMPLATE-RECORD",
            &self.public_record(),
        )
    }
}

pub fn devnet() -> PqAccountBatchAuthorizationGatewayResult<State> {
    State::devnet()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    record_root(domain, record)
}

pub fn config_id(protocol_version: &str, schema_version: &str) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(protocol_version),
            HashPart::Str(schema_version),
        ],
        32,
    )
}

pub fn lane_id(lane_kind: AuthorizationLaneKind, priority: u16, height: u64) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Int(priority as i128),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn policy_id(account_commitment: &str, mode: AccountPolicyMode, height: u64) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn batch_id(
    lane_id: &str,
    aggregator_commitment: &str,
    operation_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(aggregator_commitment),
            HashPart::Str(operation_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn attestation_id(
    batch_id: &str,
    account_commitment: &str,
    scheme: PqAttestationScheme,
    height: u64,
) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(account_commitment),
            HashPart::Str(scheme.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn sponsor_credential_id(sponsor_commitment: &str, lane_id: &str, height: u64) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SPONSOR-CREDENTIAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn replay_nullifier(
    batch_id: &str,
    account_commitment: &str,
    lane_id: &str,
    nonce_domain: &str,
    operation_index: u32,
) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-REPLAY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(account_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(nonce_domain),
            HashPart::Int(operation_index as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, lane_id: &str, height: u64) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(lane_id),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn challenge_id(
    batch_id: &str,
    challenger_commitment: &str,
    kind: ChallengeKind,
    height: u64,
) -> String {
    domain_hash(
        "PQ-ACCOUNT-BATCH-AUTH-GATEWAY-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

fn merkle_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn ensure_non_empty(value: &str, label: &str) -> PqAccountBatchAuthorizationGatewayResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PqAccountBatchAuthorizationGatewayResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> PqAccountBatchAuthorizationGatewayResult<()> {
    if current >= max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_min_capacity(value: usize, label: &str) -> PqAccountBatchAuthorizationGatewayResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_absent(condition: bool, message: &str) -> PqAccountBatchAuthorizationGatewayResult<()> {
    if condition {
        return Err(message.to_string());
    }
    Ok(())
}

fn ensure_eq(left: &str, right: &str, label: &str) -> PqAccountBatchAuthorizationGatewayResult<()> {
    if left != right {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

fn ensure_monotonic(
    next: u64,
    previous: u64,
    label: &str,
) -> PqAccountBatchAuthorizationGatewayResult<()> {
    if next < previous {
        return Err(format!("{label} must be monotonic"));
    }
    Ok(())
}
