use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateRollupFraudProofResult<T> = Result<T, String>;

pub const PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION: &str =
    "nebula-private-rollup-fraud-proof-v1";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-rollup-challenger-auth-v1";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_TRACE_ENVELOPE_SCHEME: &str =
    "ml-kem-1024+shake256-private-disputed-trace-envelope-v1";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_BISECTION_SCHEME: &str =
    "interactive-private-bisection-commitments-v1";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_WITNESS_SCHEME: &str = "private-state-witness-commitments-v1";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_VERDICT_SCHEME: &str =
    "zk-verdict-receipt-private-rollup-fraud-v1";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SLASH_ASSET_ID: &str = "dxmr";
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEVNET_HEIGHT: u64 = 768;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_AUTH_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_FAST_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_BISECTION_WINDOW_BLOCKS: u64 = 16;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_RESPONSE_WINDOW_BLOCKS: u64 = 32;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_VERDICT_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 8;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MIN_CHALLENGER_STAKE_UNITS: u64 = 50_000;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MIN_BOND_UNITS: u64 = 20_000;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SPONSORED_FEE_UNITS: u64 = 750;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 750;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_VERDICT_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SLASH_BPS: u64 = 1_000;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_BPS: u64 = 10_000;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_AUTHORIZATIONS: usize = 32_768;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_BATCH_CLAIMS: usize = 131_072;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_TRACE_ENVELOPES: usize = 262_144;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_BISECTION_ROUNDS: usize = 524_288;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_WITNESSES: usize = 262_144;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_SPONSORSHIPS: usize = 131_072;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_VERDICTS: usize = 131_072;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_SLASHING_HOOKS: usize = 131_072;
pub const PRIVATE_ROLLUP_FRAUD_PROOF_MAX_PUBLIC_RECORDS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRollupFraudProofRole {
    Challenger,
    Sequencer,
    Watchtower,
    Verifier,
    FeeSponsor,
    PrivacyGuardian,
    SlashingExecutor,
}

impl PrivateRollupFraudProofRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Challenger => "challenger",
            Self::Sequencer => "sequencer",
            Self::Watchtower => "watchtower",
            Self::Verifier => "verifier",
            Self::FeeSponsor => "fee_sponsor",
            Self::PrivacyGuardian => "privacy_guardian",
            Self::SlashingExecutor => "slashing_executor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupFraudClaimKind {
    InvalidStateTransition,
    InvalidPrivateStateDelta,
    InvalidContractExecution,
    DataAvailabilityWithholding,
    FeeOvercharge,
    NullifierReuse,
    WithdrawalRootMismatch,
    BridgeAccountingMismatch,
    SequencerEquivocation,
}

impl RollupFraudClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::InvalidPrivateStateDelta => "invalid_private_state_delta",
            Self::InvalidContractExecution => "invalid_contract_execution",
            Self::DataAvailabilityWithholding => "data_availability_withholding",
            Self::FeeOvercharge => "fee_overcharge",
            Self::NullifierReuse => "nullifier_reuse",
            Self::WithdrawalRootMismatch => "withdrawal_root_mismatch",
            Self::BridgeAccountingMismatch => "bridge_accounting_mismatch",
            Self::SequencerEquivocation => "sequencer_equivocation",
        }
    }

    pub fn fast_track(self) -> bool {
        matches!(
            self,
            Self::DataAvailabilityWithholding
                | Self::NullifierReuse
                | Self::WithdrawalRootMismatch
                | Self::SequencerEquivocation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupBatchClaimStatus {
    Posted,
    ChallengeOpen,
    Challenged,
    Accepted,
    Rejected,
    Quarantined,
    Settled,
    Expired,
}

impl RollupBatchClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Rejected | Self::Quarantined | Self::Settled | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputedTraceStatus {
    Sealed,
    Linked,
    BisectionOpen,
    WitnessRequested,
    Disclosed,
    Quarantined,
    Expired,
}

impl DisputedTraceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Linked => "linked",
            Self::BisectionOpen => "bisection_open",
            Self::WitnessRequested => "witness_requested",
            Self::Disclosed => "disclosed",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Disclosed | Self::Quarantined | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateChallengeStatus {
    Open,
    Bisection,
    AwaitingWitness,
    Verifying,
    Sustained,
    Dismissed,
    TimedOut,
    Settled,
}

impl PrivateChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bisection => "bisection",
            Self::AwaitingWitness => "awaiting_witness",
            Self::Verifying => "verifying",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::TimedOut => "timed_out",
            Self::Settled => "settled",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Sustained | Self::Dismissed | Self::TimedOut | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BisectionRoundStatus {
    Proposed,
    Countered,
    Narrowed,
    FinalStep,
    Expired,
}

impl BisectionRoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Countered => "countered",
            Self::Narrowed => "narrowed",
            Self::FinalStep => "final_step",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::FinalStep | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessVisibility {
    CommitmentsOnly,
    SelectiveDisclosure,
    VerifierEncrypted,
    PublicRedacted,
}

impl WitnessVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentsOnly => "commitments_only",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::VerifierEncrypted => "verifier_encrypted",
            Self::PublicRedacted => "public_redacted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Applied,
    Settled,
    Revoked,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudVerdictOutcome {
    FraudProven,
    FraudRejected,
    TimeoutChallenger,
    TimeoutSequencer,
    SplitFault,
    PrivacyQuarantine,
}

impl FraudVerdictOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FraudProven => "fraud_proven",
            Self::FraudRejected => "fraud_rejected",
            Self::TimeoutChallenger => "timeout_challenger",
            Self::TimeoutSequencer => "timeout_sequencer",
            Self::SplitFault => "split_fault",
            Self::PrivacyQuarantine => "privacy_quarantine",
        }
    }

    pub fn challenger_wins(self) -> bool {
        matches!(
            self,
            Self::FraudProven | Self::TimeoutSequencer | Self::SplitFault
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingHookStatus {
    Pending,
    Armed,
    Executed,
    Cancelled,
    Expired,
}

impl SlashingHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Armed => "armed",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn executable(self) -> bool {
        matches!(self, Self::Pending | Self::Armed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRollupFraudProofConfig {
    pub config_id: String,
    pub rollup_id: String,
    pub fee_asset_id: String,
    pub slash_asset_id: String,
    pub verifier_committee_root: String,
    pub privacy_guardian_root: String,
    pub slashing_executor_root: String,
    pub auth_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub fast_challenge_window_blocks: u64,
    pub bisection_window_blocks: u64,
    pub response_window_blocks: u64,
    pub verdict_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_challenger_stake_units: u64,
    pub min_bond_units: u64,
    pub sponsored_fee_units: u64,
    pub max_disclosure_bps: u64,
    pub verdict_quorum_bps: u64,
    pub default_slash_bps: u64,
}

impl Default for PrivateRollupFraudProofConfig {
    fn default() -> Self {
        let rollup_id = private_rollup_fraud_proof_string_root("rollup", "default-private-rollup");
        Self {
            config_id: private_rollup_fraud_proof_config_id(&rollup_id),
            rollup_id,
            fee_asset_id: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_FEE_ASSET_ID.to_string(),
            slash_asset_id: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SLASH_ASSET_ID.to_string(),
            verifier_committee_root: private_rollup_fraud_proof_string_root(
                "verifier-committee",
                "default-verifier-committee",
            ),
            privacy_guardian_root: private_rollup_fraud_proof_string_root(
                "privacy-guardian",
                "default-privacy-guardian",
            ),
            slashing_executor_root: private_rollup_fraud_proof_string_root(
                "slashing-executor",
                "default-slashing-executor",
            ),
            auth_ttl_blocks: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_AUTH_TTL_BLOCKS,
            challenge_window_blocks: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            fast_challenge_window_blocks:
                PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_FAST_CHALLENGE_WINDOW_BLOCKS,
            bisection_window_blocks: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_BISECTION_WINDOW_BLOCKS,
            response_window_blocks: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_RESPONSE_WINDOW_BLOCKS,
            verdict_window_blocks: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_VERDICT_WINDOW_BLOCKS,
            settlement_delay_blocks: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            min_privacy_set_size: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_challenger_stake_units:
                PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MIN_CHALLENGER_STAKE_UNITS,
            min_bond_units: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MIN_BOND_UNITS,
            sponsored_fee_units: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SPONSORED_FEE_UNITS,
            max_disclosure_bps: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MAX_DISCLOSURE_BPS,
            verdict_quorum_bps: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_VERDICT_QUORUM_BPS,
            default_slash_bps: PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SLASH_BPS,
        }
    }
}

impl PrivateRollupFraudProofConfig {
    pub fn devnet() -> Self {
        let rollup_id = private_rollup_fraud_proof_string_root("rollup", "nebula-devnet-rollup");
        Self {
            config_id: private_rollup_fraud_proof_config_id(&rollup_id),
            rollup_id,
            verifier_committee_root: private_rollup_fraud_proof_payload_root(
                "DEVNET-PRIVATE-ROLLUP-FRAUD-VERIFIERS",
                &json!({
                    "members": [
                        "devnet-private-verifier-a",
                        "devnet-private-verifier-b",
                        "devnet-private-verifier-c"
                    ],
                    "quorum_bps": PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_VERDICT_QUORUM_BPS
                }),
            ),
            privacy_guardian_root: private_rollup_fraud_proof_payload_root(
                "DEVNET-PRIVATE-ROLLUP-PRIVACY-GUARDIANS",
                &json!({
                    "redaction_required": true,
                    "max_disclosure_bps": PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_MAX_DISCLOSURE_BPS
                }),
            ),
            slashing_executor_root: private_rollup_fraud_proof_payload_root(
                "DEVNET-PRIVATE-ROLLUP-SLASHING-EXECUTORS",
                &json!({
                    "executor": "devnet-slashing-guardian",
                    "asset_id": PRIVATE_ROLLUP_FRAUD_PROOF_DEFAULT_SLASH_ASSET_ID
                }),
            ),
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_rollup_fraud_proof_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "schema_version": PRIVATE_ROLLUP_FRAUD_PROOF_SCHEMA_VERSION,
            "config_id": self.config_id,
            "rollup_id": self.rollup_id,
            "fee_asset_id": self.fee_asset_id,
            "slash_asset_id": self.slash_asset_id,
            "verifier_committee_root": self.verifier_committee_root,
            "privacy_guardian_root": self.privacy_guardian_root,
            "slashing_executor_root": self.slashing_executor_root,
            "auth_ttl_blocks": self.auth_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "fast_challenge_window_blocks": self.fast_challenge_window_blocks,
            "bisection_window_blocks": self.bisection_window_blocks,
            "response_window_blocks": self.response_window_blocks,
            "verdict_window_blocks": self.verdict_window_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_challenger_stake_units": self.min_challenger_stake_units,
            "min_bond_units": self.min_bond_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "max_disclosure_bps": self.max_disclosure_bps,
            "verdict_quorum_bps": self.verdict_quorum_bps,
            "default_slash_bps": self.default_slash_bps,
            "pq_auth_scheme": PRIVATE_ROLLUP_FRAUD_PROOF_PQ_AUTH_SCHEME,
            "trace_envelope_scheme": PRIVATE_ROLLUP_FRAUD_PROOF_TRACE_ENVELOPE_SCHEME,
            "bisection_scheme": PRIVATE_ROLLUP_FRAUD_PROOF_BISECTION_SCHEME,
            "witness_scheme": PRIVATE_ROLLUP_FRAUD_PROOF_WITNESS_SCHEME,
            "verdict_scheme": PRIVATE_ROLLUP_FRAUD_PROOF_VERDICT_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.config_id, "config id")?;
        ensure_non_empty(&self.rollup_id, "config rollup id")?;
        ensure_non_empty(&self.fee_asset_id, "config fee asset id")?;
        ensure_non_empty(&self.slash_asset_id, "config slash asset id")?;
        ensure_non_empty(&self.verifier_committee_root, "config verifier committee")?;
        ensure_non_empty(&self.privacy_guardian_root, "config privacy guardian")?;
        ensure_non_empty(&self.slashing_executor_root, "config slashing executor")?;
        ensure_positive(self.auth_ttl_blocks, "config auth ttl")?;
        ensure_positive(self.challenge_window_blocks, "config challenge window")?;
        ensure_positive(
            self.fast_challenge_window_blocks,
            "config fast challenge window",
        )?;
        ensure_positive(self.bisection_window_blocks, "config bisection window")?;
        ensure_positive(self.response_window_blocks, "config response window")?;
        ensure_positive(self.verdict_window_blocks, "config verdict window")?;
        ensure_positive(self.settlement_delay_blocks, "config settlement delay")?;
        ensure_positive(self.min_privacy_set_size, "config minimum privacy set")?;
        ensure_positive(
            self.min_challenger_stake_units,
            "config minimum challenger stake",
        )?;
        ensure_positive(self.min_bond_units, "config minimum bond")?;
        ensure_positive(self.sponsored_fee_units, "config sponsored fee")?;
        ensure_bps(self.max_disclosure_bps, "config max disclosure")?;
        ensure_bps(self.verdict_quorum_bps, "config verdict quorum")?;
        ensure_bps(self.default_slash_bps, "config default slash")?;
        if self.fast_challenge_window_blocks > self.challenge_window_blocks {
            return Err("config fast challenge window exceeds challenge window".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqChallengerAuthorization {
    pub authorization_id: String,
    pub challenger_commitment: String,
    pub role: PrivateRollupFraudProofRole,
    pub pq_public_key_commitment: String,
    pub kem_public_key_commitment: String,
    pub scope_root: String,
    pub policy_root: String,
    pub signature_root: String,
    pub stake_commitment_root: String,
    pub stake_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub active: bool,
}

impl PqChallengerAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenger_label: &str,
        role: PrivateRollupFraudProofRole,
        pq_public_key: &str,
        kem_public_key: &str,
        scopes: &[String],
        policy: &Value,
        signature_payload: &Value,
        stake_units: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(challenger_label, "authorization challenger")?;
        ensure_non_empty(pq_public_key, "authorization pq public key")?;
        ensure_non_empty(kem_public_key, "authorization kem public key")?;
        ensure_string_set(scopes, "authorization scopes")?;
        ensure_positive(stake_units, "authorization stake")?;
        validate_height_window(issued_at_height, expires_at_height, "authorization")?;

        let challenger_commitment = private_rollup_fraud_proof_account_commitment(challenger_label);
        let pq_public_key_commitment =
            private_rollup_fraud_proof_string_root("pq-public-key", pq_public_key);
        let kem_public_key_commitment =
            private_rollup_fraud_proof_string_root("kem-public-key", kem_public_key);
        let scope_root = private_rollup_fraud_proof_string_set_root("AUTH-SCOPE", scopes);
        let policy_root = private_rollup_fraud_proof_payload_root("AUTH-POLICY", policy);
        let signature_root =
            private_rollup_fraud_proof_payload_root("PQ-AUTH-SIGNATURE", signature_payload);
        let stake_commitment_root = private_rollup_fraud_proof_payload_root(
            "CHALLENGER-STAKE",
            &json!({
                "challenger_commitment": challenger_commitment,
                "stake_units": stake_units,
                "nonce": nonce
            }),
        );
        let authorization_id = private_rollup_fraud_proof_authorization_id(
            &challenger_commitment,
            role,
            &pq_public_key_commitment,
            &scope_root,
            issued_at_height,
            nonce,
        );

        let authorization = Self {
            authorization_id,
            challenger_commitment,
            role,
            pq_public_key_commitment,
            kem_public_key_commitment,
            scope_root,
            policy_root,
            signature_root,
            stake_commitment_root,
            stake_units,
            issued_at_height,
            expires_at_height,
            nonce,
            active: true,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_challenger_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "challenger_commitment": self.challenger_commitment,
            "role": self.role.as_str(),
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "kem_public_key_commitment": self.kem_public_key_commitment,
            "scope_root": self.scope_root,
            "policy_root": self.policy_root,
            "signature_root": self.signature_root,
            "stake_commitment_root": self.stake_commitment_root,
            "stake_units": self.stake_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("AUTHORIZATION", &self.public_record())
    }

    pub fn usable_at(&self, height: u64) -> bool {
        self.active && self.issued_at_height <= height && self.expires_at_height >= height
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.authorization_id, "authorization id")?;
        ensure_non_empty(&self.challenger_commitment, "authorization challenger")?;
        ensure_non_empty(
            &self.pq_public_key_commitment,
            "authorization pq public key commitment",
        )?;
        ensure_non_empty(
            &self.kem_public_key_commitment,
            "authorization kem public key commitment",
        )?;
        ensure_non_empty(&self.scope_root, "authorization scope root")?;
        ensure_non_empty(&self.policy_root, "authorization policy root")?;
        ensure_non_empty(&self.signature_root, "authorization signature root")?;
        ensure_non_empty(
            &self.stake_commitment_root,
            "authorization stake commitment",
        )?;
        ensure_positive(self.stake_units, "authorization stake")?;
        validate_height_window(
            self.issued_at_height,
            self.expires_at_height,
            "authorization",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchFraudClaim {
    pub claim_id: String,
    pub batch_id: String,
    pub batch_number: u64,
    pub sequencer_commitment: String,
    pub claim_kind: RollupFraudClaimKind,
    pub pre_state_root: String,
    pub claimed_post_state_root: String,
    pub tx_root: String,
    pub receipt_root: String,
    pub withdrawal_root: String,
    pub da_root: String,
    pub public_input_root: String,
    pub posted_at_height: u64,
    pub challenge_deadline_height: u64,
    pub status: RollupBatchClaimStatus,
}

impl RollupBatchFraudClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        batch_number: u64,
        sequencer_label: &str,
        claim_kind: RollupFraudClaimKind,
        pre_state_root: &str,
        claimed_post_state_root: &str,
        tx_root: &str,
        receipt_root: &str,
        withdrawal_root: &str,
        da_root: &str,
        posted_at_height: u64,
        challenge_window_blocks: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(batch_id, "batch claim batch id")?;
        ensure_non_empty(sequencer_label, "batch claim sequencer")?;
        ensure_non_empty(pre_state_root, "batch claim pre-state root")?;
        ensure_non_empty(claimed_post_state_root, "batch claim post-state root")?;
        ensure_non_empty(tx_root, "batch claim tx root")?;
        ensure_non_empty(receipt_root, "batch claim receipt root")?;
        ensure_non_empty(withdrawal_root, "batch claim withdrawal root")?;
        ensure_non_empty(da_root, "batch claim da root")?;
        ensure_positive(challenge_window_blocks, "batch claim challenge window")?;

        let sequencer_commitment = private_rollup_fraud_proof_account_commitment(sequencer_label);
        let public_input_root = private_rollup_fraud_proof_public_input_root(
            pre_state_root,
            claimed_post_state_root,
            tx_root,
            receipt_root,
            withdrawal_root,
            da_root,
        );
        let challenge_deadline_height = posted_at_height.saturating_add(challenge_window_blocks);
        let claim_id = private_rollup_fraud_proof_batch_claim_id(
            batch_id,
            batch_number,
            &sequencer_commitment,
            claim_kind,
            &public_input_root,
        );
        let claim = Self {
            claim_id,
            batch_id: batch_id.to_string(),
            batch_number,
            sequencer_commitment,
            claim_kind,
            pre_state_root: pre_state_root.to_string(),
            claimed_post_state_root: claimed_post_state_root.to_string(),
            tx_root: tx_root.to_string(),
            receipt_root: receipt_root.to_string(),
            withdrawal_root: withdrawal_root.to_string(),
            da_root: da_root.to_string(),
            public_input_root,
            posted_at_height,
            challenge_deadline_height,
            status: RollupBatchClaimStatus::ChallengeOpen,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_batch_fraud_claim",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "batch_id": self.batch_id,
            "batch_number": self.batch_number,
            "sequencer_commitment": self.sequencer_commitment,
            "claim_kind": self.claim_kind.as_str(),
            "pre_state_root": self.pre_state_root,
            "claimed_post_state_root": self.claimed_post_state_root,
            "tx_root": self.tx_root,
            "receipt_root": self.receipt_root,
            "withdrawal_root": self.withdrawal_root,
            "da_root": self.da_root,
            "public_input_root": self.public_input_root,
            "posted_at_height": self.posted_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("BATCH-CLAIM", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.claim_id, "claim id")?;
        ensure_non_empty(&self.batch_id, "claim batch id")?;
        ensure_non_empty(&self.sequencer_commitment, "claim sequencer")?;
        ensure_non_empty(&self.pre_state_root, "claim pre-state root")?;
        ensure_non_empty(&self.claimed_post_state_root, "claim post-state root")?;
        ensure_non_empty(&self.tx_root, "claim tx root")?;
        ensure_non_empty(&self.receipt_root, "claim receipt root")?;
        ensure_non_empty(&self.withdrawal_root, "claim withdrawal root")?;
        ensure_non_empty(&self.da_root, "claim da root")?;
        ensure_non_empty(&self.public_input_root, "claim public input root")?;
        validate_height_window(
            self.posted_at_height,
            self.challenge_deadline_height,
            "claim challenge",
        )?;
        let recomputed_root = private_rollup_fraud_proof_public_input_root(
            &self.pre_state_root,
            &self.claimed_post_state_root,
            &self.tx_root,
            &self.receipt_root,
            &self.withdrawal_root,
            &self.da_root,
        );
        if self.public_input_root != recomputed_root {
            return Err("claim public input root mismatch".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDisputedTrace {
    pub trace_id: String,
    pub claim_id: String,
    pub authorization_id: String,
    pub challenger_commitment: String,
    pub encrypted_trace_root: String,
    pub trace_step_root: String,
    pub trace_metadata_root: String,
    pub encryption_key_root: String,
    pub transcript_root: String,
    pub privacy_set_size: u64,
    pub disclosure_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: DisputedTraceStatus,
}

impl EncryptedDisputedTrace {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claim_id: &str,
        authorization: &PqChallengerAuthorization,
        encrypted_trace: &Value,
        trace_steps: &[String],
        trace_metadata: &Value,
        encryption_key_commitment: &str,
        privacy_set_size: u64,
        disclosure_bps: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(claim_id, "trace claim id")?;
        ensure_non_empty(encryption_key_commitment, "trace encryption key")?;
        ensure_string_set(trace_steps, "trace steps")?;
        ensure_positive(privacy_set_size, "trace privacy set")?;
        ensure_bps(disclosure_bps, "trace disclosure")?;
        validate_height_window(opened_at_height, expires_at_height, "trace")?;

        let encrypted_trace_root =
            private_rollup_fraud_proof_payload_root("ENCRYPTED-DISPUTED-TRACE", encrypted_trace);
        let trace_step_root =
            private_rollup_fraud_proof_string_set_root("DISPUTED-TRACE-STEPS", trace_steps);
        let trace_metadata_root =
            private_rollup_fraud_proof_payload_root("DISPUTED-TRACE-METADATA", trace_metadata);
        let encryption_key_root = private_rollup_fraud_proof_string_root(
            "TRACE-ENCRYPTION-KEY",
            encryption_key_commitment,
        );
        let transcript_root = private_rollup_fraud_proof_trace_transcript_root(
            claim_id,
            &authorization.authorization_id,
            &encrypted_trace_root,
            &trace_step_root,
            &trace_metadata_root,
        );
        let trace_id = private_rollup_fraud_proof_trace_id(
            claim_id,
            &authorization.authorization_id,
            &encrypted_trace_root,
            opened_at_height,
            nonce,
        );
        let trace = Self {
            trace_id,
            claim_id: claim_id.to_string(),
            authorization_id: authorization.authorization_id.clone(),
            challenger_commitment: authorization.challenger_commitment.clone(),
            encrypted_trace_root,
            trace_step_root,
            trace_metadata_root,
            encryption_key_root,
            transcript_root,
            privacy_set_size,
            disclosure_bps,
            opened_at_height,
            expires_at_height,
            nonce,
            status: DisputedTraceStatus::Linked,
        };
        trace.validate()?;
        Ok(trace)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_disputed_trace",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "trace_id": self.trace_id,
            "claim_id": self.claim_id,
            "authorization_id": self.authorization_id,
            "challenger_commitment": self.challenger_commitment,
            "encrypted_trace_root": self.encrypted_trace_root,
            "trace_step_root": self.trace_step_root,
            "trace_metadata_root": self.trace_metadata_root,
            "encryption_key_root": self.encryption_key_root,
            "transcript_root": self.transcript_root,
            "privacy_set_size": self.privacy_set_size,
            "disclosure_bps": self.disclosure_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("DISPUTED-TRACE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.trace_id, "trace id")?;
        ensure_non_empty(&self.claim_id, "trace claim id")?;
        ensure_non_empty(&self.authorization_id, "trace authorization id")?;
        ensure_non_empty(&self.challenger_commitment, "trace challenger")?;
        ensure_non_empty(&self.encrypted_trace_root, "trace encrypted root")?;
        ensure_non_empty(&self.trace_step_root, "trace step root")?;
        ensure_non_empty(&self.trace_metadata_root, "trace metadata root")?;
        ensure_non_empty(&self.encryption_key_root, "trace encryption key root")?;
        ensure_non_empty(&self.transcript_root, "trace transcript root")?;
        ensure_positive(self.privacy_set_size, "trace privacy set")?;
        ensure_bps(self.disclosure_bps, "trace disclosure")?;
        validate_height_window(self.opened_at_height, self.expires_at_height, "trace")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFraudChallenge {
    pub challenge_id: String,
    pub claim_id: String,
    pub trace_id: String,
    pub authorization_id: String,
    pub challenge_kind: RollupFraudClaimKind,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond_commitment_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub challenge_deadline_height: u64,
    pub response_deadline_height: u64,
    pub low_fee_sponsorship_id: Option<String>,
    pub status: PrivateChallengeStatus,
}

impl PrivateFraudChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claim: &RollupBatchFraudClaim,
        trace: &EncryptedDisputedTrace,
        challenge_kind: RollupFraudClaimKind,
        evidence_root: &str,
        bond_salt: &str,
        bond_units: u64,
        opened_at_height: u64,
        challenge_window_blocks: u64,
        response_window_blocks: u64,
        low_fee_sponsorship_id: Option<String>,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(evidence_root, "challenge evidence root")?;
        ensure_non_empty(bond_salt, "challenge bond salt")?;
        ensure_positive(bond_units, "challenge bond")?;
        ensure_positive(challenge_window_blocks, "challenge window")?;
        ensure_positive(response_window_blocks, "challenge response window")?;
        if trace.claim_id != claim.claim_id {
            return Err("challenge trace claim mismatch".to_string());
        }
        let bond_commitment_root = private_rollup_fraud_proof_payload_root(
            "CHALLENGE-BOND",
            &json!({
                "claim_id": claim.claim_id,
                "trace_id": trace.trace_id,
                "challenger_commitment": trace.challenger_commitment,
                "bond_units": bond_units,
                "salt": bond_salt
            }),
        );
        let challenge_deadline_height = opened_at_height.saturating_add(challenge_window_blocks);
        let response_deadline_height = opened_at_height.saturating_add(response_window_blocks);
        let challenge_id = private_rollup_fraud_proof_challenge_id(
            &claim.claim_id,
            &trace.trace_id,
            challenge_kind,
            &trace.challenger_commitment,
            evidence_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            claim_id: claim.claim_id.clone(),
            trace_id: trace.trace_id.clone(),
            authorization_id: trace.authorization_id.clone(),
            challenge_kind,
            challenger_commitment: trace.challenger_commitment.clone(),
            evidence_root: evidence_root.to_string(),
            bond_commitment_root,
            bond_units,
            opened_at_height,
            challenge_deadline_height,
            response_deadline_height,
            low_fee_sponsorship_id,
            status: PrivateChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fraud_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "claim_id": self.claim_id,
            "trace_id": self.trace_id,
            "authorization_id": self.authorization_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "bond_commitment_root": self.bond_commitment_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "response_deadline_height": self.response_deadline_height,
            "low_fee_sponsorship_id": self.low_fee_sponsorship_id,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("CHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.claim_id, "challenge claim id")?;
        ensure_non_empty(&self.trace_id, "challenge trace id")?;
        ensure_non_empty(&self.authorization_id, "challenge authorization id")?;
        ensure_non_empty(&self.challenger_commitment, "challenge challenger")?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        ensure_non_empty(&self.bond_commitment_root, "challenge bond commitment")?;
        ensure_positive(self.bond_units, "challenge bond")?;
        validate_height_window(
            self.opened_at_height,
            self.challenge_deadline_height,
            "challenge",
        )?;
        validate_height_window(
            self.opened_at_height,
            self.response_deadline_height,
            "challenge response",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BisectionCommitment {
    pub bisection_id: String,
    pub challenge_id: String,
    pub round_index: u64,
    pub proposer_commitment: String,
    pub left_step_index: u64,
    pub right_step_index: u64,
    pub midpoint_step_index: u64,
    pub left_state_root: String,
    pub midpoint_state_root: String,
    pub right_state_root: String,
    pub segment_commitment_root: String,
    pub encrypted_segment_root: String,
    pub response_commitment_root: String,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub status: BisectionRoundStatus,
}

impl BisectionCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: &str,
        round_index: u64,
        proposer_commitment: &str,
        left_step_index: u64,
        right_step_index: u64,
        left_state_root: &str,
        midpoint_state_root: &str,
        right_state_root: &str,
        encrypted_segment: &Value,
        opened_at_height: u64,
        bisection_window_blocks: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(challenge_id, "bisection challenge id")?;
        ensure_non_empty(proposer_commitment, "bisection proposer")?;
        ensure_non_empty(left_state_root, "bisection left state root")?;
        ensure_non_empty(midpoint_state_root, "bisection midpoint state root")?;
        ensure_non_empty(right_state_root, "bisection right state root")?;
        ensure_positive(bisection_window_blocks, "bisection window")?;
        if left_step_index >= right_step_index {
            return Err("bisection left step must be before right step".to_string());
        }
        let midpoint_step_index = left_step_index.saturating_add(
            right_step_index
                .saturating_sub(left_step_index)
                .saturating_div(2),
        );
        if midpoint_step_index <= left_step_index || midpoint_step_index >= right_step_index {
            return Err("bisection midpoint must split the disputed segment".to_string());
        }
        let encrypted_segment_root = private_rollup_fraud_proof_payload_root(
            "BISECTION-ENCRYPTED-SEGMENT",
            encrypted_segment,
        );
        let segment_commitment_root = private_rollup_fraud_proof_bisection_segment_root(
            left_step_index,
            midpoint_step_index,
            right_step_index,
            left_state_root,
            midpoint_state_root,
            right_state_root,
        );
        let response_commitment_root =
            private_rollup_fraud_proof_string_root("BISECTION-EMPTY-RESPONSE", "pending");
        let response_deadline_height = opened_at_height.saturating_add(bisection_window_blocks);
        let bisection_id = private_rollup_fraud_proof_bisection_id(
            challenge_id,
            round_index,
            proposer_commitment,
            &segment_commitment_root,
        );
        let bisection = Self {
            bisection_id,
            challenge_id: challenge_id.to_string(),
            round_index,
            proposer_commitment: proposer_commitment.to_string(),
            left_step_index,
            right_step_index,
            midpoint_step_index,
            left_state_root: left_state_root.to_string(),
            midpoint_state_root: midpoint_state_root.to_string(),
            right_state_root: right_state_root.to_string(),
            segment_commitment_root,
            encrypted_segment_root,
            response_commitment_root,
            opened_at_height,
            response_deadline_height,
            status: BisectionRoundStatus::Proposed,
        };
        bisection.validate()?;
        Ok(bisection)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bisection_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "bisection_id": self.bisection_id,
            "challenge_id": self.challenge_id,
            "round_index": self.round_index,
            "proposer_commitment": self.proposer_commitment,
            "left_step_index": self.left_step_index,
            "right_step_index": self.right_step_index,
            "midpoint_step_index": self.midpoint_step_index,
            "left_state_root": self.left_state_root,
            "midpoint_state_root": self.midpoint_state_root,
            "right_state_root": self.right_state_root,
            "segment_commitment_root": self.segment_commitment_root,
            "encrypted_segment_root": self.encrypted_segment_root,
            "response_commitment_root": self.response_commitment_root,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("BISECTION", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.bisection_id, "bisection id")?;
        ensure_non_empty(&self.challenge_id, "bisection challenge id")?;
        ensure_non_empty(&self.proposer_commitment, "bisection proposer")?;
        ensure_non_empty(&self.left_state_root, "bisection left state root")?;
        ensure_non_empty(&self.midpoint_state_root, "bisection midpoint state root")?;
        ensure_non_empty(&self.right_state_root, "bisection right state root")?;
        ensure_non_empty(&self.segment_commitment_root, "bisection segment root")?;
        ensure_non_empty(&self.encrypted_segment_root, "bisection encrypted segment")?;
        ensure_non_empty(&self.response_commitment_root, "bisection response root")?;
        validate_height_window(
            self.opened_at_height,
            self.response_deadline_height,
            "bisection",
        )?;
        if self.left_step_index >= self.midpoint_step_index
            || self.midpoint_step_index >= self.right_step_index
        {
            return Err("bisection step indexes are invalid".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateWitnessCommitment {
    pub witness_id: String,
    pub challenge_id: String,
    pub bisection_id: Option<String>,
    pub submitter_commitment: String,
    pub witness_kind: WitnessVisibility,
    pub private_state_root: String,
    pub nullifier_root: String,
    pub contract_state_root: String,
    pub encrypted_witness_root: String,
    pub verifier_access_root: String,
    pub disclosure_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateStateWitnessCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: &str,
        bisection_id: Option<String>,
        submitter_label: &str,
        witness_kind: WitnessVisibility,
        private_state_root: &str,
        nullifier_root: &str,
        contract_state_root: &str,
        encrypted_witness: &Value,
        verifier_access: &[String],
        disclosure_bps: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(challenge_id, "witness challenge id")?;
        ensure_non_empty(submitter_label, "witness submitter")?;
        ensure_non_empty(private_state_root, "witness private state root")?;
        ensure_non_empty(nullifier_root, "witness nullifier root")?;
        ensure_non_empty(contract_state_root, "witness contract state root")?;
        ensure_string_set(verifier_access, "witness verifier access")?;
        ensure_bps(disclosure_bps, "witness disclosure")?;
        validate_height_window(submitted_at_height, expires_at_height, "witness")?;

        let submitter_commitment = private_rollup_fraud_proof_account_commitment(submitter_label);
        let encrypted_witness_root =
            private_rollup_fraud_proof_payload_root("PRIVATE-STATE-WITNESS", encrypted_witness);
        let verifier_access_root =
            private_rollup_fraud_proof_string_set_root("WITNESS-VERIFIER-ACCESS", verifier_access);
        let witness_id = private_rollup_fraud_proof_witness_id(
            challenge_id,
            bisection_id.as_deref(),
            &submitter_commitment,
            witness_kind,
            &encrypted_witness_root,
            submitted_at_height,
        );
        let witness = Self {
            witness_id,
            challenge_id: challenge_id.to_string(),
            bisection_id,
            submitter_commitment,
            witness_kind,
            private_state_root: private_state_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            contract_state_root: contract_state_root.to_string(),
            encrypted_witness_root,
            verifier_access_root,
            disclosure_bps,
            submitted_at_height,
            expires_at_height,
        };
        witness.validate()?;
        Ok(witness)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_state_witness_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "witness_id": self.witness_id,
            "challenge_id": self.challenge_id,
            "bisection_id": self.bisection_id,
            "submitter_commitment": self.submitter_commitment,
            "witness_kind": self.witness_kind.as_str(),
            "private_state_root": self.private_state_root,
            "nullifier_root": self.nullifier_root,
            "contract_state_root": self.contract_state_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "verifier_access_root": self.verifier_access_root,
            "disclosure_bps": self.disclosure_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("WITNESS", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.witness_id, "witness id")?;
        ensure_non_empty(&self.challenge_id, "witness challenge id")?;
        ensure_non_empty(&self.submitter_commitment, "witness submitter")?;
        ensure_non_empty(&self.private_state_root, "witness private state root")?;
        ensure_non_empty(&self.nullifier_root, "witness nullifier root")?;
        ensure_non_empty(&self.contract_state_root, "witness contract state root")?;
        ensure_non_empty(&self.encrypted_witness_root, "witness encrypted root")?;
        ensure_non_empty(&self.verifier_access_root, "witness verifier access")?;
        ensure_bps(self.disclosure_bps, "witness disclosure")?;
        validate_height_window(self.submitted_at_height, self.expires_at_height, "witness")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeChallengeSponsorship {
    pub sponsorship_id: String,
    pub challenge_id: Option<String>,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub sponsored_fee_units: u64,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeChallengeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: Option<String>,
        sponsor_label: &str,
        beneficiary_label: &str,
        fee_asset_id: &str,
        sponsored_fee_units: u64,
        policy: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(sponsor_label, "sponsorship sponsor")?;
        ensure_non_empty(beneficiary_label, "sponsorship beneficiary")?;
        ensure_non_empty(fee_asset_id, "sponsorship fee asset")?;
        ensure_positive(sponsored_fee_units, "sponsorship fee")?;
        validate_height_window(opened_at_height, expires_at_height, "sponsorship")?;
        let sponsor_commitment = private_rollup_fraud_proof_account_commitment(sponsor_label);
        let beneficiary_commitment =
            private_rollup_fraud_proof_account_commitment(beneficiary_label);
        let policy_root = private_rollup_fraud_proof_payload_root("SPONSORSHIP-POLICY", policy);
        let sponsorship_id = private_rollup_fraud_proof_sponsorship_id(
            challenge_id.as_deref(),
            &sponsor_commitment,
            &beneficiary_commitment,
            fee_asset_id,
            sponsored_fee_units,
            opened_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            challenge_id,
            sponsor_commitment,
            beneficiary_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            sponsored_fee_units,
            policy_root,
            opened_at_height,
            expires_at_height,
            nonce,
            status: SponsorshipStatus::Offered,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_challenge_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "challenge_id": self.challenge_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "sponsored_fee_units": self.sponsored_fee_units,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor")?;
        ensure_non_empty(&self.beneficiary_commitment, "sponsorship beneficiary")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        ensure_non_empty(&self.policy_root, "sponsorship policy")?;
        ensure_positive(self.sponsored_fee_units, "sponsorship fee")?;
        validate_height_window(self.opened_at_height, self.expires_at_height, "sponsorship")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictReceipt {
    pub verdict_id: String,
    pub challenge_id: String,
    pub outcome: FraudVerdictOutcome,
    pub adjudicator_commitment: String,
    pub verdict_root: String,
    pub witness_root: String,
    pub bisection_root: String,
    pub verifier_ids_root: String,
    pub verifier_weight_bps: u64,
    pub challenger_reward_units: u64,
    pub slash_units: u64,
    pub disclosure_bps: u64,
    pub decided_at_height: u64,
    pub settlement_available_height: u64,
    pub sequence: u64,
}

impl VerdictReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: &str,
        outcome: FraudVerdictOutcome,
        adjudicator_label: &str,
        verdict_payload: &Value,
        witness_ids: &[String],
        bisection_ids: &[String],
        verifier_ids: &[String],
        verifier_weight_bps: u64,
        challenger_reward_units: u64,
        slash_units: u64,
        disclosure_bps: u64,
        decided_at_height: u64,
        settlement_delay_blocks: u64,
        sequence: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(challenge_id, "verdict challenge id")?;
        ensure_non_empty(adjudicator_label, "verdict adjudicator")?;
        ensure_string_set(verifier_ids, "verdict verifiers")?;
        ensure_bps(verifier_weight_bps, "verdict verifier weight")?;
        ensure_bps(disclosure_bps, "verdict disclosure")?;
        ensure_positive(settlement_delay_blocks, "verdict settlement delay")?;
        let adjudicator_commitment =
            private_rollup_fraud_proof_account_commitment(adjudicator_label);
        let verdict_root =
            private_rollup_fraud_proof_payload_root("VERDICT-PAYLOAD", verdict_payload);
        let witness_root =
            private_rollup_fraud_proof_string_set_root("VERDICT-WITNESSES", witness_ids);
        let bisection_root =
            private_rollup_fraud_proof_string_set_root("VERDICT-BISECTIONS", bisection_ids);
        let verifier_ids_root =
            private_rollup_fraud_proof_string_set_root("VERDICT-VERIFIERS", verifier_ids);
        let settlement_available_height = decided_at_height.saturating_add(settlement_delay_blocks);
        let verdict_id = private_rollup_fraud_proof_verdict_id(
            challenge_id,
            outcome,
            &adjudicator_commitment,
            &verdict_root,
            decided_at_height,
            sequence,
        );
        let receipt = Self {
            verdict_id,
            challenge_id: challenge_id.to_string(),
            outcome,
            adjudicator_commitment,
            verdict_root,
            witness_root,
            bisection_root,
            verifier_ids_root,
            verifier_weight_bps,
            challenger_reward_units,
            slash_units,
            disclosure_bps,
            decided_at_height,
            settlement_available_height,
            sequence,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verdict_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "verdict_id": self.verdict_id,
            "challenge_id": self.challenge_id,
            "outcome": self.outcome.as_str(),
            "adjudicator_commitment": self.adjudicator_commitment,
            "verdict_root": self.verdict_root,
            "witness_root": self.witness_root,
            "bisection_root": self.bisection_root,
            "verifier_ids_root": self.verifier_ids_root,
            "verifier_weight_bps": self.verifier_weight_bps,
            "challenger_reward_units": self.challenger_reward_units,
            "slash_units": self.slash_units,
            "disclosure_bps": self.disclosure_bps,
            "decided_at_height": self.decided_at_height,
            "settlement_available_height": self.settlement_available_height,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("VERDICT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.verdict_id, "verdict id")?;
        ensure_non_empty(&self.challenge_id, "verdict challenge id")?;
        ensure_non_empty(&self.adjudicator_commitment, "verdict adjudicator")?;
        ensure_non_empty(&self.verdict_root, "verdict root")?;
        ensure_non_empty(&self.witness_root, "verdict witness root")?;
        ensure_non_empty(&self.bisection_root, "verdict bisection root")?;
        ensure_non_empty(&self.verifier_ids_root, "verdict verifier root")?;
        ensure_bps(self.verifier_weight_bps, "verdict verifier weight")?;
        ensure_bps(self.disclosure_bps, "verdict disclosure")?;
        validate_ordered_heights(
            self.decided_at_height,
            self.settlement_available_height,
            "verdict settlement",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingHook {
    pub hook_id: String,
    pub verdict_id: String,
    pub challenge_id: String,
    pub target_commitment: String,
    pub slash_asset_id: String,
    pub slash_units: u64,
    pub slash_bps: u64,
    pub reason_root: String,
    pub executor_root: String,
    pub armed_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub status: SlashingHookStatus,
}

impl SlashingHook {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verdict: &VerdictReceipt,
        target_label: &str,
        slash_asset_id: &str,
        slash_units: u64,
        slash_bps: u64,
        reason: &Value,
        executor_root: &str,
        armed_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(target_label, "slashing target")?;
        ensure_non_empty(slash_asset_id, "slashing asset")?;
        ensure_non_empty(executor_root, "slashing executor")?;
        ensure_positive(slash_units, "slashing units")?;
        ensure_bps(slash_bps, "slashing bps")?;
        validate_height_window(armed_at_height, expires_at_height, "slashing")?;
        let target_commitment = private_rollup_fraud_proof_account_commitment(target_label);
        let reason_root = private_rollup_fraud_proof_payload_root("SLASHING-REASON", reason);
        let executable_at_height = verdict.settlement_available_height.max(armed_at_height);
        if executable_at_height > expires_at_height {
            return Err("slashing executable height exceeds expiry".to_string());
        }
        let hook_id = private_rollup_fraud_proof_slashing_hook_id(
            &verdict.verdict_id,
            &verdict.challenge_id,
            &target_commitment,
            &reason_root,
            armed_at_height,
        );
        let hook = Self {
            hook_id,
            verdict_id: verdict.verdict_id.clone(),
            challenge_id: verdict.challenge_id.clone(),
            target_commitment,
            slash_asset_id: slash_asset_id.to_string(),
            slash_units,
            slash_bps,
            reason_root,
            executor_root: executor_root.to_string(),
            armed_at_height,
            executable_at_height,
            expires_at_height,
            status: SlashingHookStatus::Armed,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "hook_id": self.hook_id,
            "verdict_id": self.verdict_id,
            "challenge_id": self.challenge_id,
            "target_commitment": self.target_commitment,
            "slash_asset_id": self.slash_asset_id,
            "slash_units": self.slash_units,
            "slash_bps": self.slash_bps,
            "reason_root": self.reason_root,
            "executor_root": self.executor_root,
            "armed_at_height": self.armed_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("SLASHING-HOOK", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.hook_id, "slashing hook id")?;
        ensure_non_empty(&self.verdict_id, "slashing verdict id")?;
        ensure_non_empty(&self.challenge_id, "slashing challenge id")?;
        ensure_non_empty(&self.target_commitment, "slashing target")?;
        ensure_non_empty(&self.slash_asset_id, "slashing asset")?;
        ensure_non_empty(&self.reason_root, "slashing reason")?;
        ensure_non_empty(&self.executor_root, "slashing executor")?;
        ensure_positive(self.slash_units, "slashing units")?;
        ensure_bps(self.slash_bps, "slashing bps")?;
        validate_ordered_heights(self.armed_at_height, self.executable_at_height, "slashing")?;
        validate_ordered_heights(
            self.executable_at_height,
            self.expires_at_height,
            "slashing",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRollupFraudProofPublicRecord {
    pub record_id: String,
    pub subject_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub public_payload: Value,
    pub disclosure_bps: u64,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl PrivateRollupFraudProofPublicRecord {
    pub fn new(
        subject_id: &str,
        record_kind: &str,
        public_payload: Value,
        disclosure_bps: u64,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PrivateRollupFraudProofResult<Self> {
        ensure_non_empty(subject_id, "public record subject")?;
        ensure_non_empty(record_kind, "public record kind")?;
        ensure_bps(disclosure_bps, "public record disclosure")?;
        let payload_root =
            private_rollup_fraud_proof_payload_root("PUBLIC-RECORD-PAYLOAD", &public_payload);
        let record_id = private_rollup_fraud_proof_public_record_id(
            subject_id,
            record_kind,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            subject_id: subject_id.to_string(),
            record_kind: record_kind.to_string(),
            payload_root,
            public_payload,
            disclosure_bps,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_rollup_fraud_proof_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "record_kind": self.record_kind,
            "payload_root": self.payload_root,
            "public_payload": self.public_payload,
            "disclosure_bps": self.disclosure_bps,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "public record subject")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        ensure_bps(self.disclosure_bps, "public record disclosure")?;
        let recomputed_root =
            private_rollup_fraud_proof_payload_root("PUBLIC-RECORD-PAYLOAD", &self.public_payload);
        if recomputed_root != self.payload_root {
            return Err("public record payload root mismatch".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRollupFraudProofRoots {
    pub config_root: String,
    pub authorization_root: String,
    pub batch_claim_root: String,
    pub trace_root: String,
    pub challenge_root: String,
    pub bisection_root: String,
    pub witness_root: String,
    pub sponsorship_root: String,
    pub verdict_root: String,
    pub slashing_hook_root: String,
    pub public_record_root: String,
}

impl PrivateRollupFraudProofRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "authorization_root": self.authorization_root,
            "batch_claim_root": self.batch_claim_root,
            "trace_root": self.trace_root,
            "challenge_root": self.challenge_root,
            "bisection_root": self.bisection_root,
            "witness_root": self.witness_root,
            "sponsorship_root": self.sponsorship_root,
            "verdict_root": self.verdict_root,
            "slashing_hook_root": self.slashing_hook_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRollupFraudProofCounters {
    pub authorization_count: u64,
    pub active_authorization_count: u64,
    pub batch_claim_count: u64,
    pub open_claim_count: u64,
    pub trace_count: u64,
    pub open_trace_count: u64,
    pub challenge_count: u64,
    pub open_challenge_count: u64,
    pub fast_track_challenge_count: u64,
    pub bisection_round_count: u64,
    pub final_bisection_round_count: u64,
    pub witness_count: u64,
    pub sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub verdict_count: u64,
    pub sustained_verdict_count: u64,
    pub slashing_hook_count: u64,
    pub executable_slashing_hook_count: u64,
    pub public_record_count: u64,
    pub total_bond_units: u64,
    pub total_sponsored_fee_units: u64,
    pub total_slash_units: u64,
}

impl PrivateRollupFraudProofCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_count": self.authorization_count,
            "active_authorization_count": self.active_authorization_count,
            "batch_claim_count": self.batch_claim_count,
            "open_claim_count": self.open_claim_count,
            "trace_count": self.trace_count,
            "open_trace_count": self.open_trace_count,
            "challenge_count": self.challenge_count,
            "open_challenge_count": self.open_challenge_count,
            "fast_track_challenge_count": self.fast_track_challenge_count,
            "bisection_round_count": self.bisection_round_count,
            "final_bisection_round_count": self.final_bisection_round_count,
            "witness_count": self.witness_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "verdict_count": self.verdict_count,
            "sustained_verdict_count": self.sustained_verdict_count,
            "slashing_hook_count": self.slashing_hook_count,
            "executable_slashing_hook_count": self.executable_slashing_hook_count,
            "public_record_count": self.public_record_count,
            "total_bond_units": self.total_bond_units,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_slash_units": self.total_slash_units,
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRollupFraudProofState {
    pub config: PrivateRollupFraudProofConfig,
    pub height: u64,
    pub nonce: u64,
    pub paused: bool,
    pub authorizations: BTreeMap<String, PqChallengerAuthorization>,
    pub batch_claims: BTreeMap<String, RollupBatchFraudClaim>,
    pub traces: BTreeMap<String, EncryptedDisputedTrace>,
    pub challenges: BTreeMap<String, PrivateFraudChallenge>,
    pub bisections: BTreeMap<String, BisectionCommitment>,
    pub witnesses: BTreeMap<String, PrivateStateWitnessCommitment>,
    pub sponsorships: BTreeMap<String, LowFeeChallengeSponsorship>,
    pub verdicts: BTreeMap<String, VerdictReceipt>,
    pub slashing_hooks: BTreeMap<String, SlashingHook>,
    pub public_records: BTreeMap<String, PrivateRollupFraudProofPublicRecord>,
}

impl Default for PrivateRollupFraudProofState {
    fn default() -> Self {
        Self::devnet()
    }
}

impl PrivateRollupFraudProofState {
    pub fn new(config: PrivateRollupFraudProofConfig, height: u64) -> Self {
        Self {
            config,
            height,
            nonce: 0,
            paused: false,
            authorizations: BTreeMap::new(),
            batch_claims: BTreeMap::new(),
            traces: BTreeMap::new(),
            challenges: BTreeMap::new(),
            bisections: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            verdicts: BTreeMap::new(),
            slashing_hooks: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = PrivateRollupFraudProofConfig::devnet();
        let mut state = Self::new(config.clone(), PRIVATE_ROLLUP_FRAUD_PROOF_DEVNET_HEIGHT);
        let scopes = vec![
            "rollup:fraud:challenge".to_string(),
            "rollup:private-trace:submit".to_string(),
            "rollup:low-fee:sponsored".to_string(),
        ];
        let authorization = PqChallengerAuthorization::new(
            "devnet-watchtower-a",
            PrivateRollupFraudProofRole::Challenger,
            "devnet-watchtower-a-ml-dsa-87-key",
            "devnet-watchtower-a-ml-kem-1024-key",
            &scopes,
            &json!({"max_disclosure_bps": config.max_disclosure_bps, "rollup_id": config.rollup_id}),
            &json!({"signature": "devnet-placeholder-pq-signature"}),
            config.min_challenger_stake_units,
            state.height,
            state.height.saturating_add(config.auth_ttl_blocks),
            1,
        );
        if let Ok(authorization) = authorization {
            let authorization_id = authorization.authorization_id.clone();
            state.authorizations.insert(authorization_id, authorization);
        }

        let claim = RollupBatchFraudClaim::new(
            "devnet-private-rollup-batch-42",
            42,
            "devnet-sequencer-a",
            RollupFraudClaimKind::InvalidPrivateStateDelta,
            &private_rollup_fraud_proof_string_root("devnet-pre-state", "42"),
            &private_rollup_fraud_proof_string_root("devnet-claimed-post-state", "43"),
            &private_rollup_fraud_proof_string_root("devnet-tx-root", "batch-42"),
            &private_rollup_fraud_proof_string_root("devnet-receipt-root", "batch-42"),
            &private_rollup_fraud_proof_string_root("devnet-withdrawal-root", "batch-42"),
            &private_rollup_fraud_proof_string_root("devnet-da-root", "batch-42"),
            state.height,
            config.challenge_window_blocks,
        );
        if let Ok(claim) = claim {
            let claim_id = claim.claim_id.clone();
            state.batch_claims.insert(claim_id.clone(), claim.clone());
            if let Some(authorization) = state.authorizations.values().next() {
                let trace_steps = vec![
                    "load-private-note".to_string(),
                    "execute-contract-call".to_string(),
                    "update-nullifier-set".to_string(),
                    "commit-post-state".to_string(),
                ];
                let trace = EncryptedDisputedTrace::new(
                    &claim_id,
                    authorization,
                    &json!({"ciphertext_root": "devnet-encrypted-trace-root"}),
                    &trace_steps,
                    &json!({"vm": "nebula-private-vm", "batch_number": 42}),
                    "devnet-trace-kem-recipient-set",
                    config.min_privacy_set_size,
                    config.max_disclosure_bps,
                    state.height,
                    state.height.saturating_add(config.challenge_window_blocks),
                    2,
                );
                if let Ok(trace) = trace {
                    let trace_id = trace.trace_id.clone();
                    state.traces.insert(trace_id.clone(), trace.clone());
                    let sponsorship = LowFeeChallengeSponsorship::new(
                        None,
                        "devnet-fee-sponsor",
                        "devnet-watchtower-a",
                        &config.fee_asset_id,
                        config.sponsored_fee_units,
                        &json!({"kind": "devnet-watchtower-subsidy"}),
                        state.height,
                        state.height.saturating_add(config.challenge_window_blocks),
                        3,
                    );
                    let sponsorship_id = sponsorship
                        .as_ref()
                        .ok()
                        .map(|item| item.sponsorship_id.clone());
                    if let Ok(sponsorship) = sponsorship {
                        state
                            .sponsorships
                            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
                    }
                    let challenge = PrivateFraudChallenge::new(
                        &claim,
                        &trace,
                        RollupFraudClaimKind::InvalidPrivateStateDelta,
                        &trace.transcript_root,
                        "devnet-bond-salt",
                        config.min_bond_units,
                        state.height,
                        config.challenge_window_blocks,
                        config.response_window_blocks,
                        sponsorship_id,
                    );
                    if let Ok(challenge) = challenge {
                        state
                            .challenges
                            .insert(challenge.challenge_id.clone(), challenge.clone());
                        let bisection = BisectionCommitment::new(
                            &challenge.challenge_id,
                            0,
                            &challenge.challenger_commitment,
                            0,
                            4,
                            &claim.pre_state_root,
                            &private_rollup_fraud_proof_string_root("devnet-mid-state", "42:2"),
                            &claim.claimed_post_state_root,
                            &json!({"encrypted_segment": "devnet-bisection-segment"}),
                            state.height,
                            config.bisection_window_blocks,
                        );
                        if let Ok(bisection) = bisection {
                            state
                                .bisections
                                .insert(bisection.bisection_id.clone(), bisection.clone());
                            let witness = PrivateStateWitnessCommitment::new(
                                &challenge.challenge_id,
                                Some(bisection.bisection_id.clone()),
                                "devnet-sequencer-a",
                                WitnessVisibility::VerifierEncrypted,
                                &private_rollup_fraud_proof_string_root(
                                    "devnet-private-state",
                                    "witness-42",
                                ),
                                &private_rollup_fraud_proof_string_root(
                                    "devnet-nullifiers",
                                    "witness-42",
                                ),
                                &private_rollup_fraud_proof_string_root(
                                    "devnet-contract-state",
                                    "witness-42",
                                ),
                                &json!({"encrypted_witness": "devnet-private-state-witness"}),
                                &["devnet-private-verifier-a".to_string()],
                                config.max_disclosure_bps,
                                state.height,
                                state.height.saturating_add(config.verdict_window_blocks),
                            );
                            if let Ok(witness) = witness {
                                state.witnesses.insert(witness.witness_id.clone(), witness);
                            }
                        }
                    }
                }
            }
        }

        let _ = state.emit_public_record(
            "devnet-private-rollup-batch-42",
            "devnet_bootstrap",
            json!({
                "message": "private rollup fraud proof devnet fixture",
                "height": state.height
            }),
            0,
        );
        state
    }

    pub fn set_height(&mut self, height: u64) -> PrivateRollupFraudProofResult<()> {
        if height < self.height {
            return Err("state height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn add_authorization(
        &mut self,
        authorization: PqChallengerAuthorization,
    ) -> PrivateRollupFraudProofResult<String> {
        authorization.validate()?;
        if authorization.stake_units < self.config.min_challenger_stake_units {
            return Err("authorization stake below configured minimum".to_string());
        }
        let id = authorization.authorization_id.clone();
        insert_unique(
            &mut self.authorizations,
            id.clone(),
            authorization,
            "authorization",
        )?;
        Ok(id)
    }

    pub fn add_batch_claim(
        &mut self,
        claim: RollupBatchFraudClaim,
    ) -> PrivateRollupFraudProofResult<String> {
        claim.validate()?;
        if claim.challenge_deadline_height
            > claim
                .posted_at_height
                .saturating_add(self.config.challenge_window_blocks)
        {
            return Err("claim challenge deadline exceeds configured window".to_string());
        }
        let id = claim.claim_id.clone();
        insert_unique(&mut self.batch_claims, id.clone(), claim, "batch claim")?;
        Ok(id)
    }

    pub fn add_trace(
        &mut self,
        trace: EncryptedDisputedTrace,
    ) -> PrivateRollupFraudProofResult<String> {
        trace.validate()?;
        require_map_key("trace claim", &trace.claim_id, &self.batch_claims)?;
        let authorization = self
            .authorizations
            .get(&trace.authorization_id)
            .ok_or_else(|| "trace references unknown authorization".to_string())?;
        if !authorization.usable_at(self.height) {
            return Err("trace authorization is not usable at current height".to_string());
        }
        if authorization.challenger_commitment != trace.challenger_commitment {
            return Err("trace challenger does not match authorization".to_string());
        }
        if trace.privacy_set_size < self.config.min_privacy_set_size {
            return Err("trace privacy set below configured minimum".to_string());
        }
        if trace.disclosure_bps > self.config.max_disclosure_bps {
            return Err("trace disclosure exceeds configured maximum".to_string());
        }
        let id = trace.trace_id.clone();
        insert_unique(&mut self.traces, id.clone(), trace, "trace")?;
        Ok(id)
    }

    pub fn add_sponsorship(
        &mut self,
        sponsorship: LowFeeChallengeSponsorship,
    ) -> PrivateRollupFraudProofResult<String> {
        sponsorship.validate()?;
        if sponsorship.sponsored_fee_units > self.config.sponsored_fee_units {
            return Err("sponsorship exceeds configured sponsored fee".to_string());
        }
        if let Some(challenge_id) = &sponsorship.challenge_id {
            require_map_key("sponsorship challenge", challenge_id, &self.challenges)?;
        }
        let id = sponsorship.sponsorship_id.clone();
        insert_unique(
            &mut self.sponsorships,
            id.clone(),
            sponsorship,
            "sponsorship",
        )?;
        Ok(id)
    }

    pub fn open_challenge(
        &mut self,
        challenge: PrivateFraudChallenge,
    ) -> PrivateRollupFraudProofResult<String> {
        challenge.validate()?;
        require_map_key("challenge claim", &challenge.claim_id, &self.batch_claims)?;
        require_map_key("challenge trace", &challenge.trace_id, &self.traces)?;
        require_map_key(
            "challenge authorization",
            &challenge.authorization_id,
            &self.authorizations,
        )?;
        if challenge.bond_units < self.config.min_bond_units {
            return Err("challenge bond below configured minimum".to_string());
        }
        if let Some(sponsorship_id) = &challenge.low_fee_sponsorship_id {
            require_map_key(
                "challenge low-fee sponsorship",
                sponsorship_id,
                &self.sponsorships,
            )?;
        }
        let claim = self
            .batch_claims
            .get(&challenge.claim_id)
            .ok_or_else(|| "challenge claim is missing".to_string())?;
        if challenge.opened_at_height > claim.challenge_deadline_height {
            return Err("challenge opened after claim deadline".to_string());
        }
        let trace = self
            .traces
            .get(&challenge.trace_id)
            .ok_or_else(|| "challenge trace is missing".to_string())?;
        if trace.claim_id != challenge.claim_id {
            return Err("challenge trace claim mismatch".to_string());
        }
        let id = challenge.challenge_id.clone();
        insert_unique(&mut self.challenges, id.clone(), challenge, "challenge")?;
        Ok(id)
    }

    pub fn add_bisection(
        &mut self,
        bisection: BisectionCommitment,
    ) -> PrivateRollupFraudProofResult<String> {
        bisection.validate()?;
        require_map_key(
            "bisection challenge",
            &bisection.challenge_id,
            &self.challenges,
        )?;
        let id = bisection.bisection_id.clone();
        insert_unique(&mut self.bisections, id.clone(), bisection, "bisection")?;
        Ok(id)
    }

    pub fn add_witness(
        &mut self,
        witness: PrivateStateWitnessCommitment,
    ) -> PrivateRollupFraudProofResult<String> {
        witness.validate()?;
        require_map_key("witness challenge", &witness.challenge_id, &self.challenges)?;
        if let Some(bisection_id) = &witness.bisection_id {
            require_map_key("witness bisection", bisection_id, &self.bisections)?;
        }
        if witness.disclosure_bps > self.config.max_disclosure_bps {
            return Err("witness disclosure exceeds configured maximum".to_string());
        }
        let id = witness.witness_id.clone();
        insert_unique(&mut self.witnesses, id.clone(), witness, "witness")?;
        Ok(id)
    }

    pub fn add_verdict(
        &mut self,
        verdict: VerdictReceipt,
    ) -> PrivateRollupFraudProofResult<String> {
        verdict.validate()?;
        require_map_key("verdict challenge", &verdict.challenge_id, &self.challenges)?;
        if verdict.verifier_weight_bps < self.config.verdict_quorum_bps {
            return Err("verdict verifier weight below configured quorum".to_string());
        }
        if verdict.disclosure_bps > self.config.max_disclosure_bps {
            return Err("verdict disclosure exceeds configured maximum".to_string());
        }
        let id = verdict.verdict_id.clone();
        insert_unique(&mut self.verdicts, id.clone(), verdict, "verdict")?;
        Ok(id)
    }

    pub fn add_slashing_hook(
        &mut self,
        hook: SlashingHook,
    ) -> PrivateRollupFraudProofResult<String> {
        hook.validate()?;
        require_map_key("slashing verdict", &hook.verdict_id, &self.verdicts)?;
        require_map_key("slashing challenge", &hook.challenge_id, &self.challenges)?;
        if hook.slash_bps > self.config.default_slash_bps {
            return Err("slashing hook exceeds configured default slash bps".to_string());
        }
        let id = hook.hook_id.clone();
        insert_unique(&mut self.slashing_hooks, id.clone(), hook, "slashing hook")?;
        Ok(id)
    }

    pub fn emit_public_record(
        &mut self,
        subject_id: &str,
        record_kind: &str,
        public_payload: Value,
        disclosure_bps: u64,
    ) -> PrivateRollupFraudProofResult<String> {
        let sequence = self.nonce;
        self.nonce = self.nonce.saturating_add(1);
        let record = PrivateRollupFraudProofPublicRecord::new(
            subject_id,
            record_kind,
            public_payload,
            disclosure_bps,
            self.height,
            sequence,
        )?;
        let id = record.record_id.clone();
        insert_unique(
            &mut self.public_records,
            id.clone(),
            record,
            "public record",
        )?;
        Ok(id)
    }

    pub fn roots(&self) -> PrivateRollupFraudProofRoots {
        PrivateRollupFraudProofRoots {
            config_root: self.config.state_root(),
            authorization_root: collection_root(
                "AUTHORIZATIONS",
                self.authorizations
                    .values()
                    .map(PqChallengerAuthorization::public_record)
                    .collect(),
            ),
            batch_claim_root: collection_root(
                "BATCH-CLAIMS",
                self.batch_claims
                    .values()
                    .map(RollupBatchFraudClaim::public_record)
                    .collect(),
            ),
            trace_root: collection_root(
                "TRACES",
                self.traces
                    .values()
                    .map(EncryptedDisputedTrace::public_record)
                    .collect(),
            ),
            challenge_root: collection_root(
                "CHALLENGES",
                self.challenges
                    .values()
                    .map(PrivateFraudChallenge::public_record)
                    .collect(),
            ),
            bisection_root: collection_root(
                "BISECTIONS",
                self.bisections
                    .values()
                    .map(BisectionCommitment::public_record)
                    .collect(),
            ),
            witness_root: collection_root(
                "WITNESSES",
                self.witnesses
                    .values()
                    .map(PrivateStateWitnessCommitment::public_record)
                    .collect(),
            ),
            sponsorship_root: collection_root(
                "SPONSORSHIPS",
                self.sponsorships
                    .values()
                    .map(LowFeeChallengeSponsorship::public_record)
                    .collect(),
            ),
            verdict_root: collection_root(
                "VERDICTS",
                self.verdicts
                    .values()
                    .map(VerdictReceipt::public_record)
                    .collect(),
            ),
            slashing_hook_root: collection_root(
                "SLASHING-HOOKS",
                self.slashing_hooks
                    .values()
                    .map(SlashingHook::public_record)
                    .collect(),
            ),
            public_record_root: collection_root(
                "PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(PrivateRollupFraudProofPublicRecord::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PrivateRollupFraudProofCounters {
        PrivateRollupFraudProofCounters {
            authorization_count: self.authorizations.len() as u64,
            active_authorization_count: self
                .authorizations
                .values()
                .filter(|authorization| authorization.usable_at(self.height))
                .count() as u64,
            batch_claim_count: self.batch_claims.len() as u64,
            open_claim_count: self
                .batch_claims
                .values()
                .filter(|claim| !claim.status.terminal())
                .count() as u64,
            trace_count: self.traces.len() as u64,
            open_trace_count: self
                .traces
                .values()
                .filter(|trace| !trace.status.terminal())
                .count() as u64,
            challenge_count: self.challenges.len() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| !challenge.status.terminal())
                .count() as u64,
            fast_track_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.challenge_kind.fast_track())
                .count() as u64,
            bisection_round_count: self.bisections.len() as u64,
            final_bisection_round_count: self
                .bisections
                .values()
                .filter(|bisection| bisection.status.terminal())
                .count() as u64,
            witness_count: self.witnesses.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            active_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| {
                    sponsorship.status.live() && sponsorship.expires_at_height >= self.height
                })
                .count() as u64,
            verdict_count: self.verdicts.len() as u64,
            sustained_verdict_count: self
                .verdicts
                .values()
                .filter(|verdict| verdict.outcome.challenger_wins())
                .count() as u64,
            slashing_hook_count: self.slashing_hooks.len() as u64,
            executable_slashing_hook_count: self
                .slashing_hooks
                .values()
                .filter(|hook| {
                    hook.status.executable()
                        && hook.executable_at_height <= self.height
                        && hook.expires_at_height >= self.height
                })
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_bond_units: self.challenges.values().fold(0_u64, |total, challenge| {
                total.saturating_add(challenge.bond_units)
            }),
            total_sponsored_fee_units: self.sponsorships.values().fold(0_u64, |total, item| {
                total.saturating_add(item.sponsored_fee_units)
            }),
            total_slash_units: self
                .slashing_hooks
                .values()
                .fold(0_u64, |total, hook| total.saturating_add(hook.slash_units)),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_rollup_fraud_proof_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION,
            "schema_version": PRIVATE_ROLLUP_FRAUD_PROOF_SCHEMA_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_rollup_fraud_proof_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateRollupFraudProofResult<String> {
        self.config.validate()?;
        ensure_capacity(
            self.authorizations.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_AUTHORIZATIONS,
            "authorization",
        )?;
        ensure_capacity(
            self.batch_claims.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_BATCH_CLAIMS,
            "batch claim",
        )?;
        ensure_capacity(
            self.traces.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_TRACE_ENVELOPES,
            "trace",
        )?;
        ensure_capacity(
            self.challenges.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_CHALLENGES,
            "challenge",
        )?;
        ensure_capacity(
            self.bisections.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_BISECTION_ROUNDS,
            "bisection",
        )?;
        ensure_capacity(
            self.witnesses.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_WITNESSES,
            "witness",
        )?;
        ensure_capacity(
            self.sponsorships.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_SPONSORSHIPS,
            "sponsorship",
        )?;
        ensure_capacity(
            self.verdicts.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_VERDICTS,
            "verdict",
        )?;
        ensure_capacity(
            self.slashing_hooks.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_SLASHING_HOOKS,
            "slashing hook",
        )?;
        ensure_capacity(
            self.public_records.len(),
            PRIVATE_ROLLUP_FRAUD_PROOF_MAX_PUBLIC_RECORDS,
            "public record",
        )?;

        for (authorization_id, authorization) in &self.authorizations {
            if authorization_id != &authorization.authorization_id {
                return Err("authorization map key does not match id".to_string());
            }
            authorization.validate()?;
            if authorization.active && authorization.expires_at_height < self.height {
                return Err("active authorization expired before state height".to_string());
            }
            if authorization.stake_units < self.config.min_challenger_stake_units {
                return Err("authorization stake below configured minimum".to_string());
            }
        }

        for (claim_id, claim) in &self.batch_claims {
            if claim_id != &claim.claim_id {
                return Err("claim map key does not match id".to_string());
            }
            claim.validate()?;
            if !claim.status.terminal() && claim.challenge_deadline_height < self.height {
                return Err("open claim expired before state height".to_string());
            }
        }

        for (trace_id, trace) in &self.traces {
            if trace_id != &trace.trace_id {
                return Err("trace map key does not match id".to_string());
            }
            trace.validate()?;
            require_map_key("trace claim", &trace.claim_id, &self.batch_claims)?;
            let authorization = self
                .authorizations
                .get(&trace.authorization_id)
                .ok_or_else(|| "trace references unknown authorization".to_string())?;
            if authorization.challenger_commitment != trace.challenger_commitment {
                return Err("trace challenger does not match authorization".to_string());
            }
            if trace.privacy_set_size < self.config.min_privacy_set_size {
                return Err("trace privacy set below configured minimum".to_string());
            }
            if trace.disclosure_bps > self.config.max_disclosure_bps {
                return Err("trace disclosure exceeds configured maximum".to_string());
            }
            if !trace.status.terminal() && trace.expires_at_height < self.height {
                return Err("open trace expired before state height".to_string());
            }
        }

        for (challenge_id, challenge) in &self.challenges {
            if challenge_id != &challenge.challenge_id {
                return Err("challenge map key does not match id".to_string());
            }
            challenge.validate()?;
            require_map_key("challenge claim", &challenge.claim_id, &self.batch_claims)?;
            require_map_key("challenge trace", &challenge.trace_id, &self.traces)?;
            require_map_key(
                "challenge authorization",
                &challenge.authorization_id,
                &self.authorizations,
            )?;
            if challenge.bond_units < self.config.min_bond_units {
                return Err("challenge bond below configured minimum".to_string());
            }
            if let Some(sponsorship_id) = &challenge.low_fee_sponsorship_id {
                require_map_key("challenge sponsorship", sponsorship_id, &self.sponsorships)?;
            }
        }

        for (bisection_id, bisection) in &self.bisections {
            if bisection_id != &bisection.bisection_id {
                return Err("bisection map key does not match id".to_string());
            }
            bisection.validate()?;
            require_map_key(
                "bisection challenge",
                &bisection.challenge_id,
                &self.challenges,
            )?;
        }

        for (witness_id, witness) in &self.witnesses {
            if witness_id != &witness.witness_id {
                return Err("witness map key does not match id".to_string());
            }
            witness.validate()?;
            require_map_key("witness challenge", &witness.challenge_id, &self.challenges)?;
            if let Some(bisection_id) = &witness.bisection_id {
                require_map_key("witness bisection", bisection_id, &self.bisections)?;
            }
            if witness.disclosure_bps > self.config.max_disclosure_bps {
                return Err("witness disclosure exceeds configured maximum".to_string());
            }
        }

        for (sponsorship_id, sponsorship) in &self.sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key does not match id".to_string());
            }
            sponsorship.validate()?;
            if sponsorship.sponsored_fee_units > self.config.sponsored_fee_units {
                return Err("sponsorship exceeds configured sponsored fee".to_string());
            }
            if let Some(challenge_id) = &sponsorship.challenge_id {
                require_map_key("sponsorship challenge", challenge_id, &self.challenges)?;
            }
            if sponsorship.status.live() && sponsorship.expires_at_height < self.height {
                return Err("live sponsorship expired before state height".to_string());
            }
        }

        for (verdict_id, verdict) in &self.verdicts {
            if verdict_id != &verdict.verdict_id {
                return Err("verdict map key does not match id".to_string());
            }
            verdict.validate()?;
            require_map_key("verdict challenge", &verdict.challenge_id, &self.challenges)?;
            if verdict.verifier_weight_bps < self.config.verdict_quorum_bps {
                return Err("verdict verifier weight below configured quorum".to_string());
            }
            if verdict.disclosure_bps > self.config.max_disclosure_bps {
                return Err("verdict disclosure exceeds configured maximum".to_string());
            }
        }

        for (hook_id, hook) in &self.slashing_hooks {
            if hook_id != &hook.hook_id {
                return Err("slashing hook map key does not match id".to_string());
            }
            hook.validate()?;
            require_map_key("slashing verdict", &hook.verdict_id, &self.verdicts)?;
            require_map_key("slashing challenge", &hook.challenge_id, &self.challenges)?;
            if hook.slash_bps > self.config.default_slash_bps {
                return Err("slashing hook exceeds configured default slash bps".to_string());
            }
        }

        for (record_id, record) in &self.public_records {
            if record_id != &record.record_id {
                return Err("public record map key does not match id".to_string());
            }
            record.validate()?;
            if record.disclosure_bps > self.config.max_disclosure_bps {
                return Err("public record disclosure exceeds configured maximum".to_string());
            }
        }

        Ok(self.state_root())
    }
}

pub fn private_rollup_fraud_proof_config_id(rollup_id: &str) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-CONFIG-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(rollup_id),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_account_commitment(account_label: &str) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-ACCOUNT",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_label),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-STRING",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_record_root(domain: &str, payload: &Value) -> String {
    private_rollup_fraud_proof_payload_root(domain, payload)
}

pub fn private_rollup_fraud_proof_state_root_from_record(record: &Value) -> String {
    private_rollup_fraud_proof_record_root("STATE", record)
}

pub fn private_rollup_fraud_proof_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-ROLLUP-FRAUD-PROOF-{domain}"), &leaves)
}

pub fn private_rollup_fraud_proof_public_input_root(
    pre_state_root: &str,
    claimed_post_state_root: &str,
    tx_root: &str,
    receipt_root: &str,
    withdrawal_root: &str,
    da_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-PUBLIC-INPUT",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pre_state_root),
            HashPart::Str(claimed_post_state_root),
            HashPart::Str(tx_root),
            HashPart::Str(receipt_root),
            HashPart::Str(withdrawal_root),
            HashPart::Str(da_root),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_authorization_id(
    challenger_commitment: &str,
    role: PrivateRollupFraudProofRole,
    pq_public_key_commitment: &str,
    scope_root: &str,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-AUTHORIZATION-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenger_commitment),
            HashPart::Str(role.as_str()),
            HashPart::Str(pq_public_key_commitment),
            HashPart::Str(scope_root),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_batch_claim_id(
    batch_id: &str,
    batch_number: u64,
    sequencer_commitment: &str,
    claim_kind: RollupFraudClaimKind,
    public_input_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-BATCH-CLAIM-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Int(batch_number as i128),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(claim_kind.as_str()),
            HashPart::Str(public_input_root),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_trace_transcript_root(
    claim_id: &str,
    authorization_id: &str,
    encrypted_trace_root: &str,
    trace_step_root: &str,
    trace_metadata_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-TRACE-TRANSCRIPT",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_id),
            HashPart::Str(authorization_id),
            HashPart::Str(encrypted_trace_root),
            HashPart::Str(trace_step_root),
            HashPart::Str(trace_metadata_root),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_trace_id(
    claim_id: &str,
    authorization_id: &str,
    encrypted_trace_root: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-TRACE-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_id),
            HashPart::Str(authorization_id),
            HashPart::Str(encrypted_trace_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_challenge_id(
    claim_id: &str,
    trace_id: &str,
    challenge_kind: RollupFraudClaimKind,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-CHALLENGE-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_id),
            HashPart::Str(trace_id),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_bisection_segment_root(
    left_step_index: u64,
    midpoint_step_index: u64,
    right_step_index: u64,
    left_state_root: &str,
    midpoint_state_root: &str,
    right_state_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-BISECTION-SEGMENT",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(left_step_index as i128),
            HashPart::Int(midpoint_step_index as i128),
            HashPart::Int(right_step_index as i128),
            HashPart::Str(left_state_root),
            HashPart::Str(midpoint_state_root),
            HashPart::Str(right_state_root),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_bisection_id(
    challenge_id: &str,
    round_index: u64,
    proposer_commitment: &str,
    segment_commitment_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-BISECTION-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Int(round_index as i128),
            HashPart::Str(proposer_commitment),
            HashPart::Str(segment_commitment_root),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_witness_id(
    challenge_id: &str,
    bisection_id: Option<&str>,
    submitter_commitment: &str,
    witness_kind: WitnessVisibility,
    encrypted_witness_root: &str,
    submitted_at_height: u64,
) -> String {
    let bisection_part = match bisection_id {
        Some(value) => value,
        None => "no-bisection",
    };
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-WITNESS-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(bisection_part),
            HashPart::Str(submitter_commitment),
            HashPart::Str(witness_kind.as_str()),
            HashPart::Str(encrypted_witness_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_sponsorship_id(
    challenge_id: Option<&str>,
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    fee_asset_id: &str,
    sponsored_fee_units: u64,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    let challenge_part = match challenge_id {
        Some(value) => value,
        None => "open-sponsorship",
    };
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-SPONSORSHIP-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_part),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_verdict_id(
    challenge_id: &str,
    outcome: FraudVerdictOutcome,
    adjudicator_commitment: &str,
    verdict_root: &str,
    decided_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-VERDICT-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(outcome.as_str()),
            HashPart::Str(adjudicator_commitment),
            HashPart::Str(verdict_root),
            HashPart::Int(decided_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_slashing_hook_id(
    verdict_id: &str,
    challenge_id: &str,
    target_commitment: &str,
    reason_root: &str,
    armed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-SLASHING-HOOK-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(verdict_id),
            HashPart::Str(challenge_id),
            HashPart::Str(target_commitment),
            HashPart::Str(reason_root),
            HashPart::Int(armed_at_height as i128),
        ],
        32,
    )
}

pub fn private_rollup_fraud_proof_public_record_id(
    subject_id: &str,
    record_kind: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-ROLLUP-FRAUD-PROOF-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PRIVATE_ROLLUP_FRAUD_PROOF_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(record_kind),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("PRIVATE-ROLLUP-FRAUD-PROOF-{domain}"), &records)
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateRollupFraudProofResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateRollupFraudProofResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateRollupFraudProofResult<()> {
    if value > PRIVATE_ROLLUP_FRAUD_PROOF_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_capacity(
    value: usize,
    capacity: usize,
    label: &str,
) -> PrivateRollupFraudProofResult<()> {
    if value > capacity {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_distinct_strings(values: &[String], label: &str) -> PrivateRollupFraudProofResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> PrivateRollupFraudProofResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    ensure_distinct_strings(values, label)
}

fn validate_height_window(start: u64, end: u64, label: &str) -> PrivateRollupFraudProofResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn validate_ordered_heights(
    start: u64,
    end: u64,
    label: &str,
) -> PrivateRollupFraudProofResult<()> {
    if end < start {
        return Err(format!("{label} heights are invalid"));
    }
    Ok(())
}

fn require_map_key<T>(
    label: &str,
    key: &str,
    map: &BTreeMap<String, T>,
) -> PrivateRollupFraudProofResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{label} references unknown id"));
    }
    Ok(())
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> PrivateRollupFraudProofResult<()> {
    if map.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    map.insert(id, record);
    Ok(())
}
