use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-contract-liquidity-escrow-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-liquidity-escrow-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEVNET_HEIGHT: u64 = 684_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_ESCROWS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_FUNDING_NOTES:
    usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_RELEASES: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize =
    128;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    usize = 512;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    25;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    15;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS: u64 =
    1_440;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_RELEASE_TTL_BLOCKS:
    u64 = 720;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowLane {
    PrivateSwap,
    ContractCall,
    PerpetualMargin,
    OptionsExercise,
    LendingDrawdown,
    BridgeLiquidity,
    TokenLaunch,
    EmergencyUnwind,
}

impl EscrowLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::PerpetualMargin => "perpetual_margin",
            Self::OptionsExercise => "options_exercise",
            Self::LendingDrawdown => "lending_drawdown",
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::TokenLaunch => "token_launch",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Open,
    Funding,
    Ready,
    Releasing,
    Settled,
    Paused,
    Slashed,
    Closed,
}

impl EscrowStatus {
    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Open | Self::Funding | Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingNoteStatus {
    Pending,
    Accepted,
    Netted,
    Released,
    Refunded,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAction {
    ExecuteContractCall,
    FillPrivateSwap,
    AddMargin,
    ExerciseOption,
    FundDrawdown,
    BridgeExit,
    RefundSender,
    EmergencyReturn,
}

impl ReleaseAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecuteContractCall => "execute_contract_call",
            Self::FillPrivateSwap => "fill_private_swap",
            Self::AddMargin => "add_margin",
            Self::ExerciseOption => "exercise_option",
            Self::FundDrawdown => "fund_drawdown",
            Self::BridgeExit => "bridge_exit",
            Self::RefundSender => "refund_sender",
            Self::EmergencyReturn => "emergency_return",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Pending,
    Authorized,
    Queued,
    Executed,
    Expired,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Repriced,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRiskVerdict {
    Low,
    Medium,
    High,
    Paused,
    Slash,
}

impl PqRiskVerdict {
    pub fn allows_release(self) -> bool {
        matches!(self, Self::Low | Self::Medium)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingBatchStatus {
    Proposed,
    Executing,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    EscrowOpened,
    FundingAccepted,
    ReleaseAuthorized,
    SponsorReserved,
    RiskAttested,
    NettingBatchBuilt,
    SettlementPublished,
    RebatePublished,
    SlashPublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EscrowOpened => "escrow_opened",
            Self::FundingAccepted => "funding_accepted",
            Self::ReleaseAuthorized => "release_authorized",
            Self::SponsorReserved => "sponsor_reserved",
            Self::RiskAttested => "risk_attested",
            Self::NettingBatchBuilt => "netting_batch_built",
            Self::SettlementPublished => "settlement_published",
            Self::RebatePublished => "rebate_published",
            Self::SlashPublished => "slash_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_escrows: usize,
    pub max_funding_notes: usize,
    pub max_release_authorizations: usize,
    pub max_sponsor_reservations: usize,
    pub max_risk_attestations: usize,
    pub max_netting_batches: usize,
    pub max_receipts: usize,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub note_ttl_blocks: u64,
    pub release_ttl_blocks: u64,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PQ_AUTH_SUITE
                    .to_string(),
            max_escrows:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_ESCROWS,
            max_funding_notes:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_FUNDING_NOTES,
            max_release_authorizations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_RELEASES,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_netting_batches:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS,
            release_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEFAULT_RELEASE_TTL_BLOCKS,
            devnet_height:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_positive("max_escrows", self.max_escrows)?;
        require_positive("max_funding_notes", self.max_funding_notes)?;
        require_positive(
            "max_release_authorizations",
            self.max_release_authorizations,
        )?;
        require_positive("max_sponsor_reservations", self.max_sponsor_reservations)?;
        require_positive("max_risk_attestations", self.max_risk_attestations)?;
        require_positive("max_netting_batches", self.max_netting_batches)?;
        require_positive("max_receipts", self.max_receipts)?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size must cover min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must be at least 192".to_string());
        }
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.target_rebate_bps > self.max_user_fee_bps {
            return Err("target_rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.note_ttl_blocks == 0 {
            return Err("note_ttl_blocks must be positive".to_string());
        }
        if self.release_ttl_blocks == 0 {
            return Err("release_ttl_blocks must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub escrow_counter: u64,
    pub funding_note_counter: u64,
    pub release_counter: u64,
    pub sponsor_reservation_counter: u64,
    pub risk_attestation_counter: u64,
    pub netting_batch_counter: u64,
    pub receipt_counter: u64,
    pub rebate_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenContractLiquidityEscrowRequest {
    pub owner_commitment: String,
    pub contract_id: String,
    pub lane: EscrowLane,
    pub asset_id: String,
    pub vault_policy_root: String,
    pub release_policy_root: String,
    pub encrypted_terms_root: String,
    pub pq_owner_authorization_root: String,
    pub initial_privacy_set_size: usize,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub escrow_nonce: String,
}

impl OpenContractLiquidityEscrowRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("owner_commitment", &self.owner_commitment)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_root("vault_policy_root", &self.vault_policy_root)?;
        require_root("release_policy_root", &self.release_policy_root)?;
        require_root("encrypted_terms_root", &self.encrypted_terms_root)?;
        require_root(
            "pq_owner_authorization_root",
            &self.pq_owner_authorization_root,
        )?;
        require_non_empty("escrow_nonce", &self.escrow_nonce)?;
        if self.initial_privacy_set_size < config.min_privacy_set_size {
            return Err("initial_privacy_set_size below runtime minimum".to_string());
        }
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("max_fee_bps exceeds runtime fee ceiling".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitShieldedFundingNoteRequest {
    pub escrow_id: String,
    pub depositor_commitment: String,
    pub note_commitment_root: String,
    pub amount_commitment_root: String,
    pub nullifier_root: String,
    pub range_proof_root: String,
    pub encrypted_note_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: usize,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub note_nonce: String,
}

impl SubmitShieldedFundingNoteRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("escrow_id", &self.escrow_id)?;
        require_non_empty("depositor_commitment", &self.depositor_commitment)?;
        require_root("note_commitment_root", &self.note_commitment_root)?;
        require_root("amount_commitment_root", &self.amount_commitment_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("range_proof_root", &self.range_proof_root)?;
        require_root("encrypted_note_root", &self.encrypted_note_root)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_non_empty("note_nonce", &self.note_nonce)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("funding note privacy set below runtime minimum".to_string());
        }
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("funding note fee exceeds runtime ceiling".to_string());
        }
        if self.expires_at_height == 0 {
            return Err("expires_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorizeEscrowReleaseRequest {
    pub escrow_id: String,
    pub funding_note_ids: Vec<String>,
    pub action: ReleaseAction,
    pub contract_call_root: String,
    pub recipient_commitment_root: String,
    pub release_amount_root: String,
    pub execution_witness_root: String,
    pub pq_multisig_authorization_root: String,
    pub release_fee_bps: u64,
    pub expires_at_height: u64,
    pub release_nonce: String,
}

impl AuthorizeEscrowReleaseRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("escrow_id", &self.escrow_id)?;
        if self.funding_note_ids.is_empty() {
            return Err("funding_note_ids cannot be empty".to_string());
        }
        require_unique("funding_note_ids", &self.funding_note_ids)?;
        require_root("contract_call_root", &self.contract_call_root)?;
        require_root("recipient_commitment_root", &self.recipient_commitment_root)?;
        require_root("release_amount_root", &self.release_amount_root)?;
        require_root("execution_witness_root", &self.execution_witness_root)?;
        require_root(
            "pq_multisig_authorization_root",
            &self.pq_multisig_authorization_root,
        )?;
        require_non_empty("release_nonce", &self.release_nonce)?;
        require_bps("release_fee_bps", self.release_fee_bps)?;
        if self.release_fee_bps > config.max_user_fee_bps {
            return Err("release_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.expires_at_height == 0 {
            return Err("release expires_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveExecutionSponsorRequest {
    pub escrow_id: String,
    pub release_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_commitment_root: String,
    pub sponsor_policy_root: String,
    pub pq_sponsor_authorization_root: String,
    pub max_sponsor_fee_bps: u64,
    pub reserved_until_height: u64,
    pub reservation_nonce: String,
}

impl ReserveExecutionSponsorRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("escrow_id", &self.escrow_id)?;
        require_non_empty("release_id", &self.release_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_root("budget_commitment_root", &self.budget_commitment_root)?;
        require_root("sponsor_policy_root", &self.sponsor_policy_root)?;
        require_root(
            "pq_sponsor_authorization_root",
            &self.pq_sponsor_authorization_root,
        )?;
        require_non_empty("reservation_nonce", &self.reservation_nonce)?;
        require_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        if self.max_sponsor_fee_bps > config.max_user_fee_bps {
            return Err("max_sponsor_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.reserved_until_height == 0 {
            return Err("reserved_until_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestEscrowRiskRequest {
    pub escrow_id: String,
    pub release_id: Option<String>,
    pub attester_commitment: String,
    pub verdict: PqRiskVerdict,
    pub risk_model_root: String,
    pub liquidity_health_root: String,
    pub market_oracle_root: String,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
    pub attestation_nonce: String,
}

impl AttestEscrowRiskRequest {
    pub fn validate(&self) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("escrow_id", &self.escrow_id)?;
        if let Some(release_id) = &self.release_id {
            require_non_empty("release_id", release_id)?;
        }
        require_non_empty("attester_commitment", &self.attester_commitment)?;
        require_root("risk_model_root", &self.risk_model_root)?;
        require_root("liquidity_health_root", &self.liquidity_health_root)?;
        require_root("market_oracle_root", &self.market_oracle_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_non_empty("attestation_nonce", &self.attestation_nonce)?;
        if self.attested_at_height == 0 {
            return Err("attested_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildLiquidityNettingBatchRequest {
    pub escrow_ids: Vec<String>,
    pub funding_note_ids: Vec<String>,
    pub release_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub batch_builder_commitment: String,
    pub netting_witness_root: String,
    pub state_delta_root: String,
    pub recursive_proof_root: String,
    pub batch_privacy_set_size: usize,
    pub total_fee_bps: u64,
    pub built_at_height: u64,
    pub batch_nonce: String,
}

impl BuildLiquidityNettingBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        if self.escrow_ids.is_empty() {
            return Err("escrow_ids cannot be empty".to_string());
        }
        if self.funding_note_ids.is_empty() {
            return Err("funding_note_ids cannot be empty".to_string());
        }
        if self.release_ids.is_empty() {
            return Err("release_ids cannot be empty".to_string());
        }
        require_unique("escrow_ids", &self.escrow_ids)?;
        require_unique("funding_note_ids", &self.funding_note_ids)?;
        require_unique("release_ids", &self.release_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_non_empty("batch_builder_commitment", &self.batch_builder_commitment)?;
        require_root("netting_witness_root", &self.netting_witness_root)?;
        require_root("state_delta_root", &self.state_delta_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_non_empty("batch_nonce", &self.batch_nonce)?;
        if self.batch_privacy_set_size < config.batch_privacy_set_size {
            return Err("batch_privacy_set_size below runtime batch target".to_string());
        }
        require_bps("total_fee_bps", self.total_fee_bps)?;
        if self.total_fee_bps > config.max_user_fee_bps {
            return Err("total_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.built_at_height == 0 {
            return Err("built_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishEscrowReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub pq_settlement_signature_root: String,
    pub emitted_at_height: u64,
    pub receipt_nonce: String,
}

impl PublishEscrowReceiptRequest {
    pub fn validate(&self) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("settlement_root", &self.settlement_root)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("state_root_after", &self.state_root_after)?;
        require_root(
            "pq_settlement_signature_root",
            &self.pq_settlement_signature_root,
        )?;
        require_non_empty("receipt_nonce", &self.receipt_nonce)?;
        if self.emitted_at_height == 0 {
            return Err("emitted_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishEscrowRebateRequest {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_commitment_root: String,
    pub settlement_receipt_id: String,
    pub pq_rebate_signature_root: String,
    pub rebate_bps: u64,
    pub emitted_at_height: u64,
    pub rebate_nonce: String,
}

impl PublishEscrowRebateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
        require_non_empty("reservation_id", &self.reservation_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("rebate_asset_id", &self.rebate_asset_id)?;
        require_root("rebate_commitment_root", &self.rebate_commitment_root)?;
        require_non_empty("settlement_receipt_id", &self.settlement_receipt_id)?;
        require_root("pq_rebate_signature_root", &self.pq_rebate_signature_root)?;
        require_non_empty("rebate_nonce", &self.rebate_nonce)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.max_user_fee_bps {
            return Err("rebate_bps exceeds runtime ceiling".to_string());
        }
        if self.emitted_at_height == 0 {
            return Err("emitted_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractLiquidityEscrowRecord {
    pub escrow_id: String,
    pub request: OpenContractLiquidityEscrowRequest,
    pub status: EscrowStatus,
    pub escrow_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ContractLiquidityEscrowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "lane": self.request.lane,
            "contract_id": self.request.contract_id,
            "asset_id": self.request.asset_id,
            "owner_commitment": self.request.owner_commitment,
            "vault_policy_root": self.request.vault_policy_root,
            "release_policy_root": self.request.release_policy_root,
            "encrypted_terms_root": self.request.encrypted_terms_root,
            "pq_owner_authorization_root": self.request.pq_owner_authorization_root,
            "initial_privacy_set_size": self.request.initial_privacy_set_size,
            "max_fee_bps": self.request.max_fee_bps,
            "status": self.status,
            "escrow_root": self.escrow_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedFundingNoteRecord {
    pub note_id: String,
    pub request: SubmitShieldedFundingNoteRequest,
    pub status: FundingNoteStatus,
    pub accepted_root: String,
    pub accepted_at_height: u64,
}

impl ShieldedFundingNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "escrow_id": self.request.escrow_id,
            "depositor_commitment": self.request.depositor_commitment,
            "note_commitment_root": self.request.note_commitment_root,
            "amount_commitment_root": self.request.amount_commitment_root,
            "nullifier_root": self.request.nullifier_root,
            "range_proof_root": self.request.range_proof_root,
            "encrypted_note_root": self.request.encrypted_note_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "max_fee_bps": self.request.max_fee_bps,
            "expires_at_height": self.request.expires_at_height,
            "status": self.status,
            "accepted_root": self.accepted_root,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscrowReleaseAuthorizationRecord {
    pub release_id: String,
    pub request: AuthorizeEscrowReleaseRequest,
    pub status: ReleaseStatus,
    pub release_root: String,
    pub authorized_at_height: u64,
}

impl EscrowReleaseAuthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "escrow_id": self.request.escrow_id,
            "funding_note_ids": self.request.funding_note_ids,
            "action": self.request.action,
            "contract_call_root": self.request.contract_call_root,
            "recipient_commitment_root": self.request.recipient_commitment_root,
            "release_amount_root": self.request.release_amount_root,
            "execution_witness_root": self.request.execution_witness_root,
            "pq_multisig_authorization_root": self.request.pq_multisig_authorization_root,
            "release_fee_bps": self.request.release_fee_bps,
            "expires_at_height": self.request.expires_at_height,
            "status": self.status,
            "release_root": self.release_root,
            "authorized_at_height": self.authorized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveExecutionSponsorRequest,
    pub status: SponsorReservationStatus,
    pub reservation_root: String,
    pub reserved_at_height: u64,
}

impl ExecutionSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "escrow_id": self.request.escrow_id,
            "release_id": self.request.release_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "fee_asset_id": self.request.fee_asset_id,
            "budget_commitment_root": self.request.budget_commitment_root,
            "sponsor_policy_root": self.request.sponsor_policy_root,
            "pq_sponsor_authorization_root": self.request.pq_sponsor_authorization_root,
            "max_sponsor_fee_bps": self.request.max_sponsor_fee_bps,
            "reserved_until_height": self.request.reserved_until_height,
            "status": self.status,
            "reservation_root": self.reservation_root,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscrowRiskAttestationRecord {
    pub attestation_id: String,
    pub request: AttestEscrowRiskRequest,
    pub attestation_root: String,
}

impl EscrowRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "escrow_id": self.request.escrow_id,
            "release_id": self.request.release_id,
            "attester_commitment": self.request.attester_commitment,
            "verdict": self.request.verdict,
            "risk_model_root": self.request.risk_model_root,
            "liquidity_health_root": self.request.liquidity_health_root,
            "market_oracle_root": self.request.market_oracle_root,
            "pq_signature_root": self.request.pq_signature_root,
            "attested_at_height": self.request.attested_at_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingBatchRecord {
    pub batch_id: String,
    pub request: BuildLiquidityNettingBatchRequest,
    pub status: NettingBatchStatus,
    pub batch_root: String,
    pub state_root_after: String,
}

impl LiquidityNettingBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "escrow_ids": self.request.escrow_ids,
            "funding_note_ids": self.request.funding_note_ids,
            "release_ids": self.request.release_ids,
            "reservation_ids": self.request.reservation_ids,
            "batch_builder_commitment": self.request.batch_builder_commitment,
            "netting_witness_root": self.request.netting_witness_root,
            "state_delta_root": self.request.state_delta_root,
            "recursive_proof_root": self.request.recursive_proof_root,
            "batch_privacy_set_size": self.request.batch_privacy_set_size,
            "total_fee_bps": self.request.total_fee_bps,
            "built_at_height": self.request.built_at_height,
            "status": self.status,
            "batch_root": self.batch_root,
            "state_root_after": self.state_root_after,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscrowReceiptRecord {
    pub receipt_id: String,
    pub request: PublishEscrowReceiptRequest,
    pub receipt_root: String,
}

impl EscrowReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.request.subject_id,
            "receipt_kind": self.request.receipt_kind,
            "settlement_root": self.request.settlement_root,
            "state_root_before": self.request.state_root_before,
            "state_root_after": self.request.state_root_after,
            "pq_settlement_signature_root": self.request.pq_settlement_signature_root,
            "emitted_at_height": self.request.emitted_at_height,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscrowRebateRecord {
    pub rebate_id: String,
    pub request: PublishEscrowRebateRequest,
    pub rebate_root: String,
}

impl EscrowRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.request.reservation_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "rebate_asset_id": self.request.rebate_asset_id,
            "rebate_commitment_root": self.request.rebate_commitment_root,
            "settlement_receipt_id": self.request.settlement_receipt_id,
            "pq_rebate_signature_root": self.request.pq_rebate_signature_root,
            "rebate_bps": self.request.rebate_bps,
            "emitted_at_height": self.request.emitted_at_height,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub escrow_root: String,
    pub funding_note_root: String,
    pub release_root: String,
    pub sponsor_reservation_root: String,
    pub risk_attestation_root: String,
    pub netting_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub escrows: BTreeMap<String, ContractLiquidityEscrowRecord>,
    pub funding_notes: BTreeMap<String, ShieldedFundingNoteRecord>,
    pub release_authorizations: BTreeMap<String, EscrowReleaseAuthorizationRecord>,
    pub sponsor_reservations: BTreeMap<String, ExecutionSponsorReservationRecord>,
    pub risk_attestations: BTreeMap<String, EscrowRiskAttestationRecord>,
    pub netting_batches: BTreeMap<String, LiquidityNettingBatchRecord>,
    pub receipts: BTreeMap<String, EscrowReceiptRecord>,
    pub rebates: BTreeMap<String, EscrowRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            escrows: BTreeMap::new(),
            funding_notes: BTreeMap::new(),
            release_authorizations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_contract_escrow(
        &mut self,
        request: OpenContractLiquidityEscrowRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<ContractLiquidityEscrowRecord>
    {
        request.validate(&self.config)?;
        if self.escrows.len() >= self.config.max_escrows {
            return Err("contract liquidity escrow capacity exhausted".to_string());
        }
        self.counters.escrow_counter = self.counters.escrow_counter.saturating_add(1);
        let escrow_id = contract_liquidity_escrow_id(&request, self.counters.escrow_counter);
        if self.escrows.contains_key(&escrow_id) {
            return Err(format!("duplicate contract liquidity escrow {escrow_id}"));
        }
        let escrow_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-ESCROW",
            &request.public_record(),
        );
        let record = ContractLiquidityEscrowRecord {
            escrow_id: escrow_id.clone(),
            request,
            status: EscrowStatus::Open,
            escrow_root,
            created_at_height: self.config.devnet_height,
            updated_at_height: self.config.devnet_height,
        };
        self.escrows.insert(escrow_id, record.clone());
        Ok(record)
    }

    pub fn submit_shielded_funding_note(
        &mut self,
        request: SubmitShieldedFundingNoteRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<ShieldedFundingNoteRecord> {
        request.validate(&self.config)?;
        if self.funding_notes.len() >= self.config.max_funding_notes {
            return Err("shielded funding note capacity exhausted".to_string());
        }
        {
            let escrow = self.require_escrow(&request.escrow_id)?;
            if !escrow.status.accepts_funding() {
                return Err(format!(
                    "escrow {} does not accept funding notes",
                    request.escrow_id
                ));
            }
        }
        if request.expires_at_height
            < self
                .config
                .devnet_height
                .saturating_add(self.config.note_ttl_blocks / 8)
        {
            return Err("funding note expiry is too near".to_string());
        }
        if self.consumed_nullifiers.contains(&request.nullifier_root) {
            return Err("funding note nullifier already consumed".to_string());
        }
        self.counters.funding_note_counter = self.counters.funding_note_counter.saturating_add(1);
        let note_id = shielded_funding_note_id(&request, self.counters.funding_note_counter);
        let accepted_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-FUNDING-NOTE",
            &request.public_record(),
        );
        let record = ShieldedFundingNoteRecord {
            note_id: note_id.clone(),
            request: request.clone(),
            status: FundingNoteStatus::Accepted,
            accepted_root,
            accepted_at_height: self.config.devnet_height,
        };
        self.consumed_nullifiers
            .insert(request.nullifier_root.clone());
        self.funding_notes.insert(note_id, record.clone());
        if let Some(escrow) = self.escrows.get_mut(&request.escrow_id) {
            escrow.status = EscrowStatus::Ready;
            escrow.updated_at_height = self.config.devnet_height;
        }
        Ok(record)
    }

    pub fn authorize_escrow_release(
        &mut self,
        request: AuthorizeEscrowReleaseRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<EscrowReleaseAuthorizationRecord>
    {
        request.validate(&self.config)?;
        if self.release_authorizations.len() >= self.config.max_release_authorizations {
            return Err("release authorization capacity exhausted".to_string());
        }
        let escrow = self.require_escrow(&request.escrow_id)?;
        if !matches!(escrow.status, EscrowStatus::Ready | EscrowStatus::Releasing) {
            return Err(format!(
                "escrow {} is not ready for release",
                request.escrow_id
            ));
        }
        for note_id in &request.funding_note_ids {
            let note = self.require_funding_note(note_id)?;
            if note.request.escrow_id != request.escrow_id {
                return Err(format!(
                    "funding note {note_id} does not belong to escrow {}",
                    request.escrow_id
                ));
            }
            if note.status != FundingNoteStatus::Accepted {
                return Err(format!("funding note {note_id} is not accepted"));
            }
        }
        if let Some(attestation) = self.latest_risk_for_escrow(&request.escrow_id) {
            if !attestation.request.verdict.allows_release() {
                return Err("latest PQ risk verdict blocks escrow release".to_string());
            }
        }
        self.counters.release_counter = self.counters.release_counter.saturating_add(1);
        let release_id = escrow_release_authorization_id(&request, self.counters.release_counter);
        let release_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RELEASE",
            &request.public_record(),
        );
        let record = EscrowReleaseAuthorizationRecord {
            release_id: release_id.clone(),
            request: request.clone(),
            status: ReleaseStatus::Authorized,
            release_root,
            authorized_at_height: self.config.devnet_height,
        };
        self.release_authorizations
            .insert(release_id, record.clone());
        if let Some(escrow) = self.escrows.get_mut(&request.escrow_id) {
            escrow.status = EscrowStatus::Releasing;
            escrow.updated_at_height = self.config.devnet_height;
        }
        Ok(record)
    }

    pub fn reserve_execution_sponsor(
        &mut self,
        request: ReserveExecutionSponsorRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<ExecutionSponsorReservationRecord>
    {
        request.validate(&self.config)?;
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("execution sponsor reservation capacity exhausted".to_string());
        }
        self.require_escrow(&request.escrow_id)?;
        let release = self.require_release(&request.release_id)?;
        if release.request.escrow_id != request.escrow_id {
            return Err("release does not belong to escrow".to_string());
        }
        if !matches!(
            release.status,
            ReleaseStatus::Authorized | ReleaseStatus::Queued
        ) {
            return Err("release is not sponsorable".to_string());
        }
        self.counters.sponsor_reservation_counter =
            self.counters.sponsor_reservation_counter.saturating_add(1);
        let reservation_id =
            execution_sponsor_reservation_id(&request, self.counters.sponsor_reservation_counter);
        let reservation_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-SPONSOR",
            &request.public_record(),
        );
        let record = ExecutionSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: SponsorReservationStatus::Reserved,
            reservation_root,
            reserved_at_height: self.config.devnet_height,
        };
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn attest_escrow_risk(
        &mut self,
        request: AttestEscrowRiskRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<EscrowRiskAttestationRecord>
    {
        request.validate()?;
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("risk attestation capacity exhausted".to_string());
        }
        self.require_escrow(&request.escrow_id)?;
        if let Some(release_id) = &request.release_id {
            self.require_release(release_id)?;
        }
        self.counters.risk_attestation_counter =
            self.counters.risk_attestation_counter.saturating_add(1);
        let attestation_id =
            escrow_risk_attestation_id(&request, self.counters.risk_attestation_counter);
        let attestation_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RISK",
            &request.public_record(),
        );
        let verdict = request.verdict;
        let escrow_id = request.escrow_id.clone();
        let record = EscrowRiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            attestation_root,
        };
        self.risk_attestations
            .insert(attestation_id, record.clone());
        if let Some(escrow) = self.escrows.get_mut(&escrow_id) {
            escrow.status = match verdict {
                PqRiskVerdict::Paused => EscrowStatus::Paused,
                PqRiskVerdict::Slash => EscrowStatus::Slashed,
                _ => escrow.status,
            };
            escrow.updated_at_height = self.config.devnet_height;
        }
        Ok(record)
    }

    pub fn build_liquidity_netting_batch(
        &mut self,
        request: BuildLiquidityNettingBatchRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<LiquidityNettingBatchRecord>
    {
        request.validate(&self.config)?;
        if self.netting_batches.len() >= self.config.max_netting_batches {
            return Err("liquidity netting batch capacity exhausted".to_string());
        }
        for escrow_id in &request.escrow_ids {
            self.require_escrow(escrow_id)?;
        }
        for note_id in &request.funding_note_ids {
            self.require_funding_note(note_id)?;
        }
        for release_id in &request.release_ids {
            self.require_release(release_id)?;
        }
        for reservation_id in &request.reservation_ids {
            self.require_reservation(reservation_id)?;
        }
        self.counters.netting_batch_counter = self.counters.netting_batch_counter.saturating_add(1);
        let batch_id = liquidity_netting_batch_id(&request, self.counters.netting_batch_counter);
        let batch_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-NETTING-BATCH",
            &request.public_record(),
        );
        for note_id in &request.funding_note_ids {
            if let Some(note) = self.funding_notes.get_mut(note_id) {
                note.status = FundingNoteStatus::Netted;
            }
        }
        for release_id in &request.release_ids {
            if let Some(release) = self.release_authorizations.get_mut(release_id) {
                release.status = ReleaseStatus::Queued;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
            }
        }
        let state_root_after = state_root_from_record(&json!({
            "batch_root": batch_root,
            "previous_state_root": self.state_root(),
            "batch_counter": self.counters.netting_batch_counter,
        }));
        let record = LiquidityNettingBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: NettingBatchStatus::Proposed,
            batch_root,
            state_root_after,
        };
        self.netting_batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishEscrowReceiptRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<EscrowReceiptRecord> {
        request.validate()?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("escrow receipt capacity exhausted".to_string());
        }
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let receipt_id = escrow_receipt_id(&request, self.counters.receipt_counter);
        let receipt_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RECEIPT",
            &request.public_record(),
        );
        let record = EscrowReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            receipt_root,
        };
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishEscrowRebateRequest,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<EscrowRebateRecord> {
        request.validate(&self.config)?;
        if self.rebates.len() >= self.config.max_receipts {
            return Err("escrow rebate capacity exhausted".to_string());
        }
        self.require_reservation(&request.reservation_id)?;
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        let rebate_id = escrow_rebate_id(&request, self.counters.rebate_counter);
        let rebate_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-REBATE",
            &request.public_record(),
        );
        let record = EscrowRebateRecord {
            rebate_id: rebate_id.clone(),
            request: request.clone(),
            rebate_root,
        };
        if let Some(reservation) = self.sponsor_reservations.get_mut(&request.reservation_id) {
            reservation.status = SponsorReservationStatus::RebateQueued;
        }
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let escrow_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-ESCROWS",
            &self
                .escrows
                .values()
                .map(ContractLiquidityEscrowRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let funding_note_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-FUNDING-NOTES",
            &self
                .funding_notes
                .values()
                .map(ShieldedFundingNoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let release_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RELEASES",
            &self
                .release_authorizations
                .values()
                .map(EscrowReleaseAuthorizationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-SPONSORS",
            &self
                .sponsor_reservations
                .values()
                .map(ExecutionSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_attestation_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RISK-ATTESTATIONS",
            &self
                .risk_attestations
                .values()
                .map(EscrowRiskAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let netting_batch_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-NETTING-BATCHES",
            &self
                .netting_batches
                .values()
                .map(LiquidityNettingBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RECEIPTS",
            &self
                .receipts
                .values()
                .map(EscrowReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-REBATES",
            &self
                .rebates
                .values()
                .map(EscrowRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "escrow_root": escrow_root,
            "funding_note_root": funding_note_root,
            "release_root": release_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "risk_attestation_root": risk_attestation_root,
            "netting_batch_root": netting_batch_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            escrow_root,
            funding_note_root,
            release_root,
            sponsor_reservation_root,
            risk_attestation_root,
            netting_batch_root,
            receipt_root,
            rebate_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_escrow(
        &self,
        escrow_id: &str,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<&ContractLiquidityEscrowRecord>
    {
        self.escrows
            .get(escrow_id)
            .ok_or_else(|| format!("unknown contract liquidity escrow {escrow_id}"))
    }

    fn require_funding_note(
        &self,
        note_id: &str,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<&ShieldedFundingNoteRecord> {
        self.funding_notes
            .get(note_id)
            .ok_or_else(|| format!("unknown shielded funding note {note_id}"))
    }

    fn require_release(
        &self,
        release_id: &str,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<&EscrowReleaseAuthorizationRecord>
    {
        self.release_authorizations
            .get(release_id)
            .ok_or_else(|| format!("unknown escrow release authorization {release_id}"))
    }

    fn require_reservation(
        &self,
        reservation_id: &str,
    ) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<&ExecutionSponsorReservationRecord>
    {
        self.sponsor_reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown execution sponsor reservation {reservation_id}"))
    }

    fn latest_risk_for_escrow(&self, escrow_id: &str) -> Option<&EscrowRiskAttestationRecord> {
        self.risk_attestations
            .values()
            .filter(|attestation| attestation.request.escrow_id == escrow_id)
            .max_by_key(|attestation| attestation.request.attested_at_height)
    }
}

pub type Runtime = State;

pub fn contract_liquidity_escrow_id(
    request: &OpenContractLiquidityEscrowRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.contract_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.asset_id),
            HashPart::Str(&request.vault_policy_root),
            HashPart::Str(&request.escrow_nonce),
        ],
        32,
    )
}

pub fn shielded_funding_note_id(
    request: &SubmitShieldedFundingNoteRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-FUNDING-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.escrow_id),
            HashPart::Str(&request.depositor_commitment),
            HashPart::Str(&request.note_commitment_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.note_nonce),
        ],
        32,
    )
}

pub fn escrow_release_authorization_id(
    request: &AuthorizeEscrowReleaseRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RELEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.escrow_id),
            HashPart::Str(&id_list_root("funding_notes", &request.funding_note_ids)),
            HashPart::Str(request.action.as_str()),
            HashPart::Str(&request.contract_call_root),
            HashPart::Str(&request.release_nonce),
        ],
        32,
    )
}

pub fn execution_sponsor_reservation_id(
    request: &ReserveExecutionSponsorRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.escrow_id),
            HashPart::Str(&request.release_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Str(&request.reservation_nonce),
        ],
        32,
    )
}

pub fn escrow_risk_attestation_id(request: &AttestEscrowRiskRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RISK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.escrow_id),
            HashPart::Str(request.release_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(&request.risk_model_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn liquidity_netting_batch_id(
    request: &BuildLiquidityNettingBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-NETTING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("escrows", &request.escrow_ids)),
            HashPart::Str(&id_list_root("funding_notes", &request.funding_note_ids)),
            HashPart::Str(&id_list_root("releases", &request.release_ids)),
            HashPart::Str(&request.netting_witness_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn escrow_receipt_id(request: &PublishEscrowReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.receipt_nonce),
        ],
        32,
    )
}

pub fn escrow_rebate_id(request: &PublishEscrowRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-STATE",
        record,
    )
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-CONFIDENTIAL-CONTRACT-LIQUIDITY-ESCROW-ID-LIST-{domain}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_root(
    field: &str,
    value: &str,
) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_positive(
    field: &str,
    value: usize,
) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(
    field: &str,
    value: u64,
) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_CONTRACT_LIQUIDITY_ESCROW_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2ConfidentialContractLiquidityEscrowRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}
