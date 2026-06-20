use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateFraudEvidenceMarketResult<T> = Result<T, String>;

pub const PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION: &str =
    "nebula-private-fraud-evidence-market-v1";
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_ENVELOPE_SCHEME: &str =
    "ml-kem-1024+shake256-fraud-evidence-envelope-devnet-v1";
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-reporter-authorization-v1";
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DISCLOSURE_SCHEME: &str =
    "privacy-safe-disclosure-ticket-v1";
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_VERDICT_SCHEME: &str =
    "zk-verdict-receipt-fraud-market-devnet-v1";
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_BOUNTY_ASSET_ID: &str = "dxmr";
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEVNET_HEIGHT: u64 = 704;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_AUTH_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 288;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_VERDICT_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MIN_REPORTER_STAKE_UNITS: u64 = 25_000;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MIN_BOUNTY_UNITS: u64 = 10_000;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_SPONSORED_FEE_UNITS: u64 = 500;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_000;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_VERDICT_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_BPS: u64 = 10_000;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_AUTHORIZATIONS: usize = 32_768;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_ENVELOPES: usize = 131_072;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_BOUNTIES: usize = 65_536;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_SPONSORSHIPS: usize = 65_536;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_DISCLOSURE_TICKETS: usize = 131_072;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_VERDICT_RECEIPTS: usize = 131_072;
pub const PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_PUBLIC_RECORDS: usize = 131_072;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudDomain {
    Rollup,
    Bridge,
    Contract,
    Proof,
}

impl FraudDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rollup => "rollup",
            Self::Bridge => "bridge",
            Self::Contract => "contract",
            Self::Proof => "proof",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudEvidenceKind {
    InvalidStateTransition,
    DataAvailabilityWithholding,
    InvalidBridgeRelease,
    DoubleSpend,
    ContractConstraintViolation,
    PrivateStateLeak,
    InvalidRecursiveProof,
    VerifierEquivocation,
    Custom(String),
}

impl FraudEvidenceKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::InvalidStateTransition => "invalid_state_transition".to_string(),
            Self::DataAvailabilityWithholding => "data_availability_withholding".to_string(),
            Self::InvalidBridgeRelease => "invalid_bridge_release".to_string(),
            Self::DoubleSpend => "double_spend".to_string(),
            Self::ContractConstraintViolation => "contract_constraint_violation".to_string(),
            Self::PrivateStateLeak => "private_state_leak".to_string(),
            Self::InvalidRecursiveProof => "invalid_recursive_proof".to_string(),
            Self::VerifierEquivocation => "verifier_equivocation".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn high_severity(&self) -> bool {
        matches!(
            self,
            Self::InvalidStateTransition
                | Self::InvalidBridgeRelease
                | Self::DoubleSpend
                | Self::InvalidRecursiveProof
                | Self::VerifierEquivocation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReporterAuthorizationStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl ReporterAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEnvelopeStatus {
    Sealed,
    Listed,
    Matched,
    Challenged,
    Disclosed,
    Quarantined,
    Settled,
    Expired,
}

impl EvidenceEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Listed => "listed",
            Self::Matched => "matched",
            Self::Challenged => "challenged",
            Self::Disclosed => "disclosed",
            Self::Quarantined => "quarantined",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Quarantined | Self::Settled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeBountyStatus {
    Open,
    Reserved,
    Awarded,
    Refunded,
    Expired,
    Slashed,
}

impl ChallengeBountyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Awarded => "awarded",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
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
pub enum DisclosureTicketStatus {
    Issued,
    Exercised,
    Revoked,
    Expired,
}

impl DisclosureTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Exercised => "exercised",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Issued | Self::Exercised)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOutcome {
    FraudProven,
    FraudRejected,
    InsufficientDisclosure,
    PrivacyViolation,
    Timeout,
    SplitFault,
}

impl VerdictOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FraudProven => "fraud_proven",
            Self::FraudRejected => "fraud_rejected",
            Self::InsufficientDisclosure => "insufficient_disclosure",
            Self::PrivacyViolation => "privacy_violation",
            Self::Timeout => "timeout",
            Self::SplitFault => "split_fault",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFraudEvidenceMarketConfig {
    pub market_id: String,
    pub operator_committee_root: String,
    pub disclosure_council_root: String,
    pub verdict_committee_root: String,
    pub fee_asset_id: String,
    pub bounty_asset_id: String,
    pub auth_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub verdict_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_reporter_stake_units: u64,
    pub min_bounty_units: u64,
    pub sponsored_fee_units: u64,
    pub max_disclosure_bps: u64,
    pub verdict_quorum_bps: u64,
}

impl Default for PrivateFraudEvidenceMarketConfig {
    fn default() -> Self {
        Self {
            market_id: private_fraud_evidence_market_string_root("market", "default"),
            operator_committee_root: private_fraud_evidence_market_string_root(
                "operator-committee",
                "default-fraud-evidence-committee",
            ),
            disclosure_council_root: private_fraud_evidence_market_string_root(
                "disclosure-council",
                "default-privacy-disclosure-council",
            ),
            verdict_committee_root: private_fraud_evidence_market_string_root(
                "verdict-committee",
                "default-fraud-verdict-committee",
            ),
            fee_asset_id: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_FEE_ASSET_ID.to_string(),
            bounty_asset_id: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_BOUNTY_ASSET_ID.to_string(),
            auth_ttl_blocks: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_AUTH_TTL_BLOCKS,
            disclosure_ttl_blocks: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            challenge_window_blocks: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            verdict_window_blocks: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_VERDICT_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reporter_stake_units:
                PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MIN_REPORTER_STAKE_UNITS,
            min_bounty_units: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MIN_BOUNTY_UNITS,
            sponsored_fee_units: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_SPONSORED_FEE_UNITS,
            max_disclosure_bps: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MAX_DISCLOSURE_BPS,
            verdict_quorum_bps: PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_VERDICT_QUORUM_BPS,
        }
    }
}

impl PrivateFraudEvidenceMarketConfig {
    pub fn devnet() -> Self {
        Self {
            market_id: private_fraud_evidence_market_string_root("market", "devnet"),
            operator_committee_root: private_fraud_evidence_market_payload_root(
                "DEVNET-FRAUD-EVIDENCE-COMMITTEE",
                &json!({
                    "members": [
                        "devnet-fraud-watchtower-a",
                        "devnet-pq-reporter-b",
                        "devnet-disclosure-guardian-c"
                    ],
                    "threshold": 2
                }),
            ),
            disclosure_council_root: private_fraud_evidence_market_payload_root(
                "DEVNET-DISCLOSURE-COUNCIL",
                &json!({
                    "privacy_safe_tickets": true,
                    "redaction_required": true,
                    "max_disclosure_bps": PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_MAX_DISCLOSURE_BPS
                }),
            ),
            verdict_committee_root: private_fraud_evidence_market_payload_root(
                "DEVNET-VERDICT-COMMITTEE",
                &json!({
                    "receipt_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_VERDICT_SCHEME,
                    "quorum_bps": PRIVATE_FRAUD_EVIDENCE_MARKET_DEFAULT_VERDICT_QUORUM_BPS
                }),
            ),
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fraud_evidence_market_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "schema_version": PRIVATE_FRAUD_EVIDENCE_MARKET_SCHEMA_VERSION,
            "market_id": self.market_id,
            "operator_committee_root": self.operator_committee_root,
            "disclosure_council_root": self.disclosure_council_root,
            "verdict_committee_root": self.verdict_committee_root,
            "fee_asset_id": self.fee_asset_id,
            "bounty_asset_id": self.bounty_asset_id,
            "auth_ttl_blocks": self.auth_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "verdict_window_blocks": self.verdict_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_reporter_stake_units": self.min_reporter_stake_units,
            "min_bounty_units": self.min_bounty_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "max_disclosure_bps": self.max_disclosure_bps,
            "verdict_quorum_bps": self.verdict_quorum_bps,
            "envelope_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_ENVELOPE_SCHEME,
            "pq_auth_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_PQ_AUTH_SCHEME,
            "disclosure_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_DISCLOSURE_SCHEME,
            "verdict_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_VERDICT_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.market_id, "config market id")?;
        ensure_non_empty(
            &self.operator_committee_root,
            "config operator committee root",
        )?;
        ensure_non_empty(
            &self.disclosure_council_root,
            "config disclosure council root",
        )?;
        ensure_non_empty(
            &self.verdict_committee_root,
            "config verdict committee root",
        )?;
        ensure_non_empty(&self.fee_asset_id, "config fee asset id")?;
        ensure_non_empty(&self.bounty_asset_id, "config bounty asset id")?;
        ensure_positive(self.auth_ttl_blocks, "config auth ttl")?;
        ensure_positive(self.disclosure_ttl_blocks, "config disclosure ttl")?;
        ensure_positive(self.challenge_window_blocks, "config challenge window")?;
        ensure_positive(self.verdict_window_blocks, "config verdict window")?;
        ensure_positive(self.min_privacy_set_size, "config minimum privacy set")?;
        ensure_positive(
            self.min_reporter_stake_units,
            "config minimum reporter stake",
        )?;
        ensure_positive(self.min_bounty_units, "config minimum bounty")?;
        ensure_positive(self.sponsored_fee_units, "config sponsored fee")?;
        ensure_bps(self.max_disclosure_bps, "config max disclosure")?;
        ensure_bps(self.verdict_quorum_bps, "config verdict quorum")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReporterAuthorization {
    pub authorization_id: String,
    pub reporter_commitment: String,
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
    pub status: ReporterAuthorizationStatus,
}

impl PqReporterAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reporter_label: &str,
        pq_public_key: &str,
        kem_public_key: &str,
        scopes: &[String],
        policy: &Value,
        signature_payload: &Value,
        stake_units: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateFraudEvidenceMarketResult<Self> {
        ensure_non_empty(reporter_label, "authorization reporter")?;
        ensure_non_empty(pq_public_key, "authorization pq public key")?;
        ensure_non_empty(kem_public_key, "authorization kem public key")?;
        ensure_string_set(scopes, "authorization scopes")?;
        ensure_positive(stake_units, "authorization stake")?;
        validate_height_window(issued_at_height, expires_at_height, "authorization")?;

        let reporter_commitment = private_fraud_evidence_market_account_commitment(reporter_label);
        let pq_public_key_commitment =
            private_fraud_evidence_market_string_root("pq-public-key", pq_public_key);
        let kem_public_key_commitment =
            private_fraud_evidence_market_string_root("kem-public-key", kem_public_key);
        let scope_root = private_fraud_evidence_market_string_set_root("AUTH-SCOPE", scopes);
        let policy_root = private_fraud_evidence_market_payload_root("AUTH-POLICY", policy);
        let signature_root =
            private_fraud_evidence_market_payload_root("PQ-AUTH-SIGNATURE", signature_payload);
        let stake_commitment_root = private_fraud_evidence_market_payload_root(
            "REPORTER-STAKE",
            &json!({
                "reporter_commitment": reporter_commitment,
                "stake_units": stake_units,
                "nonce": nonce
            }),
        );
        let authorization_id = private_fraud_evidence_market_authorization_id(
            &reporter_commitment,
            &pq_public_key_commitment,
            &scope_root,
            issued_at_height,
            nonce,
        );

        let authorization = Self {
            authorization_id,
            reporter_commitment,
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
            status: ReporterAuthorizationStatus::Active,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_reporter_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "reporter_commitment": self.reporter_commitment,
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
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("REPORTER-AUTHORIZATION", &self.public_record())
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.authorization_id, "authorization id")?;
        ensure_non_empty(&self.reporter_commitment, "authorization reporter")?;
        ensure_non_empty(
            &self.pq_public_key_commitment,
            "authorization pq public key",
        )?;
        ensure_non_empty(
            &self.kem_public_key_commitment,
            "authorization kem public key",
        )?;
        ensure_non_empty(&self.scope_root, "authorization scope root")?;
        ensure_non_empty(&self.policy_root, "authorization policy root")?;
        ensure_non_empty(&self.signature_root, "authorization signature root")?;
        ensure_non_empty(&self.stake_commitment_root, "authorization stake root")?;
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
pub struct EncryptedEvidenceEnvelope {
    pub envelope_id: String,
    pub authorization_id: String,
    pub reporter_commitment: String,
    pub fraud_domain: FraudDomain,
    pub evidence_kind: FraudEvidenceKind,
    pub subject_id: String,
    pub encrypted_payload_root: String,
    pub encrypted_key_root: String,
    pub metadata_commitment_root: String,
    pub redaction_policy_root: String,
    pub nullifier_root: String,
    pub report_context_root: String,
    pub privacy_set_size: u64,
    pub disclosure_bps: u64,
    pub requested_bounty_units: u64,
    pub sponsored_fee_units: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: EvidenceEnvelopeStatus,
}

impl EncryptedEvidenceEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: impl Into<String>,
        reporter_commitment: impl Into<String>,
        fraud_domain: FraudDomain,
        evidence_kind: FraudEvidenceKind,
        subject_id: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        encrypted_key_root: impl Into<String>,
        metadata_commitment_root: impl Into<String>,
        redaction_policy_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        report_context: &Value,
        privacy_set_size: u64,
        disclosure_bps: u64,
        requested_bounty_units: u64,
        sponsored_fee_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateFraudEvidenceMarketResult<Self> {
        let authorization_id = authorization_id.into();
        let reporter_commitment = reporter_commitment.into();
        let subject_id = subject_id.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let encrypted_key_root = encrypted_key_root.into();
        let metadata_commitment_root = metadata_commitment_root.into();
        let redaction_policy_root = redaction_policy_root.into();
        let nullifier_root = nullifier_root.into();
        let report_context_root =
            private_fraud_evidence_market_payload_root("REPORT-CONTEXT", report_context);
        let envelope_id = private_fraud_evidence_market_envelope_id(
            &authorization_id,
            fraud_domain,
            &evidence_kind,
            &subject_id,
            &encrypted_payload_root,
            nonce,
        );

        let envelope = Self {
            envelope_id,
            authorization_id,
            reporter_commitment,
            fraud_domain,
            evidence_kind,
            subject_id,
            encrypted_payload_root,
            encrypted_key_root,
            metadata_commitment_root,
            redaction_policy_root,
            nullifier_root,
            report_context_root,
            privacy_set_size,
            disclosure_bps,
            requested_bounty_units,
            sponsored_fee_units,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: EvidenceEnvelopeStatus::Listed,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_fraud_evidence_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "authorization_id": self.authorization_id,
            "reporter_commitment": self.reporter_commitment,
            "fraud_domain": self.fraud_domain.as_str(),
            "evidence_kind": self.evidence_kind.as_str(),
            "subject_id": self.subject_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "encrypted_key_root": self.encrypted_key_root,
            "metadata_commitment_root": self.metadata_commitment_root,
            "redaction_policy_root": self.redaction_policy_root,
            "nullifier_root": self.nullifier_root,
            "report_context_root": self.report_context_root,
            "privacy_set_size": self.privacy_set_size,
            "disclosure_bps": self.disclosure_bps,
            "requested_bounty_units": self.requested_bounty_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "envelope_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_ENVELOPE_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root(
            "ENCRYPTED-EVIDENCE-ENVELOPE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.envelope_id, "envelope id")?;
        ensure_non_empty(&self.authorization_id, "envelope authorization id")?;
        ensure_non_empty(&self.reporter_commitment, "envelope reporter")?;
        ensure_non_empty(&self.subject_id, "envelope subject")?;
        ensure_non_empty(&self.encrypted_payload_root, "envelope payload root")?;
        ensure_non_empty(&self.encrypted_key_root, "envelope key root")?;
        ensure_non_empty(&self.metadata_commitment_root, "envelope metadata root")?;
        ensure_non_empty(&self.redaction_policy_root, "envelope redaction root")?;
        ensure_non_empty(&self.nullifier_root, "envelope nullifier root")?;
        ensure_non_empty(&self.report_context_root, "envelope context root")?;
        ensure_positive(self.privacy_set_size, "envelope privacy set")?;
        ensure_bps(self.disclosure_bps, "envelope disclosure")?;
        ensure_positive(self.requested_bounty_units, "envelope requested bounty")?;
        validate_height_window(self.submitted_at_height, self.expires_at_height, "envelope")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBounty {
    pub bounty_id: String,
    pub sponsor_commitment: String,
    pub fraud_domain: FraudDomain,
    pub evidence_kind: FraudEvidenceKind,
    pub subject_id: String,
    pub bounty_asset_id: String,
    pub bounty_units: u64,
    pub match_policy_root: String,
    pub reserved_envelope_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: ChallengeBountyStatus,
}

impl ChallengeBounty {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        fraud_domain: FraudDomain,
        evidence_kind: FraudEvidenceKind,
        subject_id: impl Into<String>,
        bounty_asset_id: impl Into<String>,
        bounty_units: u64,
        match_policy: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateFraudEvidenceMarketResult<Self> {
        ensure_non_empty(sponsor_label, "bounty sponsor")?;
        let sponsor_commitment = private_fraud_evidence_market_account_commitment(sponsor_label);
        let subject_id = subject_id.into();
        let bounty_asset_id = bounty_asset_id.into();
        let match_policy_root =
            private_fraud_evidence_market_payload_root("BOUNTY-MATCH-POLICY", match_policy);
        let bounty_id = private_fraud_evidence_market_bounty_id(
            &sponsor_commitment,
            fraud_domain,
            &evidence_kind,
            &subject_id,
            bounty_units,
            opened_at_height,
            nonce,
        );
        let bounty = Self {
            bounty_id,
            sponsor_commitment,
            fraud_domain,
            evidence_kind,
            subject_id,
            bounty_asset_id,
            bounty_units,
            match_policy_root,
            reserved_envelope_id: None,
            opened_at_height,
            expires_at_height,
            nonce,
            status: ChallengeBountyStatus::Open,
        };
        bounty.validate()?;
        Ok(bounty)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_bounty",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "bounty_id": self.bounty_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fraud_domain": self.fraud_domain.as_str(),
            "evidence_kind": self.evidence_kind.as_str(),
            "subject_id": self.subject_id,
            "bounty_asset_id": self.bounty_asset_id,
            "bounty_units": self.bounty_units,
            "match_policy_root": self.match_policy_root,
            "reserved_envelope_id": self.reserved_envelope_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("CHALLENGE-BOUNTY", &self.public_record())
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.bounty_id, "bounty id")?;
        ensure_non_empty(&self.sponsor_commitment, "bounty sponsor")?;
        ensure_non_empty(&self.subject_id, "bounty subject")?;
        ensure_non_empty(&self.bounty_asset_id, "bounty asset")?;
        ensure_non_empty(&self.match_policy_root, "bounty match policy")?;
        ensure_positive(self.bounty_units, "bounty units")?;
        validate_height_window(self.opened_at_height, self.expires_at_height, "bounty")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSponsorship {
    pub sponsorship_id: String,
    pub envelope_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub sponsored_fee_units: u64,
    pub low_fee_lane: String,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: SponsorshipStatus,
}

impl EvidenceSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope_id: impl Into<String>,
        sponsor_label: &str,
        fee_asset_id: impl Into<String>,
        sponsored_fee_units: u64,
        low_fee_lane: impl Into<String>,
        policy: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateFraudEvidenceMarketResult<Self> {
        ensure_non_empty(sponsor_label, "sponsorship sponsor")?;
        let envelope_id = envelope_id.into();
        let sponsor_commitment = private_fraud_evidence_market_account_commitment(sponsor_label);
        let fee_asset_id = fee_asset_id.into();
        let low_fee_lane = low_fee_lane.into();
        let policy_root = private_fraud_evidence_market_payload_root("SPONSORSHIP-POLICY", policy);
        let sponsorship_id = private_fraud_evidence_market_sponsorship_id(
            &envelope_id,
            &sponsor_commitment,
            &fee_asset_id,
            sponsored_fee_units,
            opened_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            envelope_id,
            sponsor_commitment,
            fee_asset_id,
            sponsored_fee_units,
            low_fee_lane,
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
            "kind": "evidence_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "envelope_id": self.envelope_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "sponsored_fee_units": self.sponsored_fee_units,
            "low_fee_lane": self.low_fee_lane,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("EVIDENCE-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.envelope_id, "sponsorship envelope id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        ensure_non_empty(&self.low_fee_lane, "sponsorship low fee lane")?;
        ensure_non_empty(&self.policy_root, "sponsorship policy root")?;
        ensure_positive(self.sponsored_fee_units, "sponsorship fee units")?;
        validate_height_window(self.opened_at_height, self.expires_at_height, "sponsorship")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySafeDisclosureTicket {
    pub ticket_id: String,
    pub envelope_id: String,
    pub requester_commitment: String,
    pub purpose_root: String,
    pub redaction_root: String,
    pub view_key_commitment: String,
    pub disclosure_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub exercised_at_height: Option<u64>,
    pub nonce: u64,
    pub status: DisclosureTicketStatus,
}

impl PrivacySafeDisclosureTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope_id: impl Into<String>,
        requester_label: &str,
        purpose: &Value,
        redaction: &Value,
        view_key: &str,
        disclosure_bps: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateFraudEvidenceMarketResult<Self> {
        ensure_non_empty(requester_label, "ticket requester")?;
        ensure_non_empty(view_key, "ticket view key")?;
        let envelope_id = envelope_id.into();
        let requester_commitment =
            private_fraud_evidence_market_account_commitment(requester_label);
        let purpose_root =
            private_fraud_evidence_market_payload_root("DISCLOSURE-PURPOSE", purpose);
        let redaction_root =
            private_fraud_evidence_market_payload_root("DISCLOSURE-REDACTION", redaction);
        let view_key_commitment = private_fraud_evidence_market_string_root("view-key", view_key);
        let ticket_id = private_fraud_evidence_market_disclosure_ticket_id(
            &envelope_id,
            &requester_commitment,
            &purpose_root,
            disclosure_bps,
            issued_at_height,
            nonce,
        );
        let ticket = Self {
            ticket_id,
            envelope_id,
            requester_commitment,
            purpose_root,
            redaction_root,
            view_key_commitment,
            disclosure_bps,
            issued_at_height,
            expires_at_height,
            exercised_at_height: None,
            nonce,
            status: DisclosureTicketStatus::Issued,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_safe_disclosure_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "envelope_id": self.envelope_id,
            "requester_commitment": self.requester_commitment,
            "purpose_root": self.purpose_root,
            "redaction_root": self.redaction_root,
            "view_key_commitment": self.view_key_commitment,
            "disclosure_bps": self.disclosure_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "exercised_at_height": self.exercised_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "disclosure_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_DISCLOSURE_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("DISCLOSURE-TICKET", &self.public_record())
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.ticket_id, "ticket id")?;
        ensure_non_empty(&self.envelope_id, "ticket envelope id")?;
        ensure_non_empty(&self.requester_commitment, "ticket requester")?;
        ensure_non_empty(&self.purpose_root, "ticket purpose root")?;
        ensure_non_empty(&self.redaction_root, "ticket redaction root")?;
        ensure_non_empty(&self.view_key_commitment, "ticket view key")?;
        ensure_bps(self.disclosure_bps, "ticket disclosure")?;
        validate_height_window(self.issued_at_height, self.expires_at_height, "ticket")?;
        if let Some(exercised_at_height) = self.exercised_at_height {
            if exercised_at_height < self.issued_at_height {
                return Err("ticket exercise height precedes issuance".to_string());
            }
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictReceipt {
    pub receipt_id: String,
    pub envelope_id: String,
    pub bounty_id: Option<String>,
    pub ticket_id: Option<String>,
    pub outcome: VerdictOutcome,
    pub adjudicator_commitment: String,
    pub verdict_root: String,
    pub disclosure_root: String,
    pub settlement_root: String,
    pub awarded_bounty_units: u64,
    pub reporter_reward_units: u64,
    pub verifier_weight_bps: u64,
    pub decided_at_height: u64,
    pub sequence: u64,
}

impl VerdictReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope_id: impl Into<String>,
        bounty_id: Option<String>,
        ticket_id: Option<String>,
        outcome: VerdictOutcome,
        adjudicator_label: &str,
        verdict_payload: &Value,
        disclosure_payload: &Value,
        settlement_payload: &Value,
        awarded_bounty_units: u64,
        reporter_reward_units: u64,
        verifier_weight_bps: u64,
        decided_at_height: u64,
        sequence: u64,
    ) -> PrivateFraudEvidenceMarketResult<Self> {
        ensure_non_empty(adjudicator_label, "verdict adjudicator")?;
        let envelope_id = envelope_id.into();
        let adjudicator_commitment =
            private_fraud_evidence_market_account_commitment(adjudicator_label);
        let verdict_root = private_fraud_evidence_market_payload_root("VERDICT", verdict_payload);
        let disclosure_root =
            private_fraud_evidence_market_payload_root("VERDICT-DISCLOSURE", disclosure_payload);
        let settlement_root =
            private_fraud_evidence_market_payload_root("VERDICT-SETTLEMENT", settlement_payload);
        let receipt_id = private_fraud_evidence_market_verdict_receipt_id(
            &envelope_id,
            outcome,
            &adjudicator_commitment,
            &verdict_root,
            decided_at_height,
            sequence,
        );
        let receipt = Self {
            receipt_id,
            envelope_id,
            bounty_id,
            ticket_id,
            outcome,
            adjudicator_commitment,
            verdict_root,
            disclosure_root,
            settlement_root,
            awarded_bounty_units,
            reporter_reward_units,
            verifier_weight_bps,
            decided_at_height,
            sequence,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verdict_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "envelope_id": self.envelope_id,
            "bounty_id": self.bounty_id,
            "ticket_id": self.ticket_id,
            "outcome": self.outcome.as_str(),
            "adjudicator_commitment": self.adjudicator_commitment,
            "verdict_root": self.verdict_root,
            "disclosure_root": self.disclosure_root,
            "settlement_root": self.settlement_root,
            "awarded_bounty_units": self.awarded_bounty_units,
            "reporter_reward_units": self.reporter_reward_units,
            "verifier_weight_bps": self.verifier_weight_bps,
            "decided_at_height": self.decided_at_height,
            "sequence": self.sequence,
            "verdict_scheme": PRIVATE_FRAUD_EVIDENCE_MARKET_VERDICT_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("VERDICT-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.envelope_id, "receipt envelope id")?;
        ensure_non_empty(&self.adjudicator_commitment, "receipt adjudicator")?;
        ensure_non_empty(&self.verdict_root, "receipt verdict root")?;
        ensure_non_empty(&self.disclosure_root, "receipt disclosure root")?;
        ensure_non_empty(&self.settlement_root, "receipt settlement root")?;
        ensure_bps(self.verifier_weight_bps, "receipt verifier weight")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudMarketPublicRecord {
    pub record_id: String,
    pub subject_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub disclosure_bps: u64,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl FraudMarketPublicRecord {
    pub fn new(
        subject_id: impl Into<String>,
        record_kind: impl Into<String>,
        payload: &Value,
        disclosure_bps: u64,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PrivateFraudEvidenceMarketResult<Self> {
        let subject_id = subject_id.into();
        let record_kind = record_kind.into();
        let payload_root = private_fraud_evidence_market_payload_root("PUBLIC-RECORD", payload);
        let record_id = private_fraud_evidence_market_public_record_id(
            &subject_id,
            &record_kind,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            subject_id,
            record_kind,
            payload_root,
            disclosure_bps,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fraud_market_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "record_kind": self.record_kind,
            "payload_root": self.payload_root,
            "disclosure_bps": self.disclosure_bps,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "public record subject")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        ensure_bps(self.disclosure_bps, "public record disclosure")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFraudEvidenceMarketRoots {
    pub config_root: String,
    pub authorization_root: String,
    pub envelope_root: String,
    pub bounty_root: String,
    pub sponsorship_root: String,
    pub disclosure_ticket_root: String,
    pub verdict_receipt_root: String,
    pub public_record_root: String,
}

impl PrivateFraudEvidenceMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "authorization_root": self.authorization_root,
            "envelope_root": self.envelope_root,
            "bounty_root": self.bounty_root,
            "sponsorship_root": self.sponsorship_root,
            "disclosure_ticket_root": self.disclosure_ticket_root,
            "verdict_receipt_root": self.verdict_receipt_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFraudEvidenceMarketCounters {
    pub authorization_count: u64,
    pub active_authorization_count: u64,
    pub envelope_count: u64,
    pub open_envelope_count: u64,
    pub high_severity_envelope_count: u64,
    pub bounty_count: u64,
    pub open_bounty_count: u64,
    pub sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub disclosure_ticket_count: u64,
    pub usable_disclosure_ticket_count: u64,
    pub verdict_receipt_count: u64,
    pub public_record_count: u64,
    pub total_bounty_units: u64,
    pub total_sponsored_fee_units: u64,
}

impl PrivateFraudEvidenceMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_count": self.authorization_count,
            "active_authorization_count": self.active_authorization_count,
            "envelope_count": self.envelope_count,
            "open_envelope_count": self.open_envelope_count,
            "high_severity_envelope_count": self.high_severity_envelope_count,
            "bounty_count": self.bounty_count,
            "open_bounty_count": self.open_bounty_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "disclosure_ticket_count": self.disclosure_ticket_count,
            "usable_disclosure_ticket_count": self.usable_disclosure_ticket_count,
            "verdict_receipt_count": self.verdict_receipt_count,
            "public_record_count": self.public_record_count,
            "total_bounty_units": self.total_bounty_units,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFraudEvidenceMarketState {
    pub config: PrivateFraudEvidenceMarketConfig,
    pub height: u64,
    pub nonce: u64,
    pub authorizations: BTreeMap<String, PqReporterAuthorization>,
    pub envelopes: BTreeMap<String, EncryptedEvidenceEnvelope>,
    pub bounties: BTreeMap<String, ChallengeBounty>,
    pub sponsorships: BTreeMap<String, EvidenceSponsorship>,
    pub disclosure_tickets: BTreeMap<String, PrivacySafeDisclosureTicket>,
    pub verdict_receipts: BTreeMap<String, VerdictReceipt>,
    pub public_records: BTreeMap<String, FraudMarketPublicRecord>,
}

impl Default for PrivateFraudEvidenceMarketState {
    fn default() -> Self {
        Self {
            config: PrivateFraudEvidenceMarketConfig::default(),
            height: 0,
            nonce: 0,
            authorizations: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            bounties: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            disclosure_tickets: BTreeMap::new(),
            verdict_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl PrivateFraudEvidenceMarketState {
    pub fn devnet() -> PrivateFraudEvidenceMarketResult<Self> {
        let mut state = Self {
            config: PrivateFraudEvidenceMarketConfig::devnet(),
            height: PRIVATE_FRAUD_EVIDENCE_MARKET_DEVNET_HEIGHT,
            nonce: 1,
            ..Self::default()
        };

        let scopes = vec![
            "rollup.invalid_state_transition".to_string(),
            "bridge.invalid_release".to_string(),
            "proof.invalid_recursive_proof".to_string(),
        ];
        let authorization = PqReporterAuthorization::new(
            "devnet-fraud-reporter-a",
            "devnet-reporter-a-ml-dsa-public-key",
            "devnet-reporter-a-ml-kem-public-key",
            &scopes,
            &json!({"max_disclosure_bps": state.config.max_disclosure_bps}),
            &json!({"signature": "devnet-pq-signature-root"}),
            state.config.min_reporter_stake_units,
            state.height,
            state.height + state.config.auth_ttl_blocks,
            state.next_nonce(),
        )?;
        state.insert_authorization(authorization.clone())?;

        let envelope = EncryptedEvidenceEnvelope::new(
            authorization.authorization_id.clone(),
            authorization.reporter_commitment.clone(),
            FraudDomain::Rollup,
            FraudEvidenceKind::InvalidStateTransition,
            "devnet-rollup-batch-42",
            private_fraud_evidence_market_string_root("encrypted-payload", "devnet-envelope"),
            private_fraud_evidence_market_string_root("encrypted-key", "devnet-envelope"),
            private_fraud_evidence_market_string_root("metadata", "devnet-envelope"),
            private_fraud_evidence_market_string_root("redaction-policy", "devnet-envelope"),
            private_fraud_evidence_market_string_root("nullifier", "devnet-envelope"),
            &json!({"batch": 42, "transition": 7}),
            state.config.min_privacy_set_size,
            250,
            state.config.min_bounty_units,
            state.config.sponsored_fee_units,
            state.height,
            state.height + state.config.challenge_window_blocks,
            state.next_nonce(),
        )?;
        state.insert_envelope(envelope.clone())?;

        let bounty = ChallengeBounty::new(
            "devnet-challenge-sponsor-a",
            FraudDomain::Rollup,
            FraudEvidenceKind::InvalidStateTransition,
            envelope.subject_id.clone(),
            state.config.bounty_asset_id.clone(),
            state.config.min_bounty_units.saturating_mul(2),
            &json!({"domain": "rollup", "severity": "high"}),
            state.height,
            state.height + state.config.challenge_window_blocks,
            state.next_nonce(),
        )?;
        state.insert_bounty(bounty)?;

        let ticket = PrivacySafeDisclosureTicket::new(
            envelope.envelope_id.clone(),
            "devnet-disclosure-council-a",
            &json!({"purpose": "fraud-adjudication"}),
            &json!({"redact": ["account_labels", "raw_view_keys"]}),
            "devnet-ticket-view-key",
            250,
            state.height,
            state.height + state.config.disclosure_ttl_blocks,
            state.next_nonce(),
        )?;
        state.insert_disclosure_ticket(ticket)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateFraudEvidenceMarketResult<String> {
        if height < self.height {
            return Err("market height cannot move backwards".to_string());
        }
        self.height = height;
        self.validate()
    }

    pub fn next_nonce(&mut self) -> u64 {
        let nonce = self.nonce;
        self.nonce = self.nonce.saturating_add(1);
        nonce
    }

    pub fn insert_authorization(
        &mut self,
        authorization: PqReporterAuthorization,
    ) -> PrivateFraudEvidenceMarketResult<()> {
        insert_unique(
            &mut self.authorizations,
            authorization.authorization_id.clone(),
            authorization,
            "authorization",
        )
    }

    pub fn insert_envelope(
        &mut self,
        envelope: EncryptedEvidenceEnvelope,
    ) -> PrivateFraudEvidenceMarketResult<()> {
        insert_unique(
            &mut self.envelopes,
            envelope.envelope_id.clone(),
            envelope,
            "envelope",
        )
    }

    pub fn insert_bounty(
        &mut self,
        bounty: ChallengeBounty,
    ) -> PrivateFraudEvidenceMarketResult<()> {
        insert_unique(
            &mut self.bounties,
            bounty.bounty_id.clone(),
            bounty,
            "bounty",
        )
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: EvidenceSponsorship,
    ) -> PrivateFraudEvidenceMarketResult<()> {
        insert_unique(
            &mut self.sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "sponsorship",
        )
    }

    pub fn insert_disclosure_ticket(
        &mut self,
        ticket: PrivacySafeDisclosureTicket,
    ) -> PrivateFraudEvidenceMarketResult<()> {
        insert_unique(
            &mut self.disclosure_tickets,
            ticket.ticket_id.clone(),
            ticket,
            "disclosure ticket",
        )
    }

    pub fn insert_verdict_receipt(
        &mut self,
        receipt: VerdictReceipt,
    ) -> PrivateFraudEvidenceMarketResult<()> {
        insert_unique(
            &mut self.verdict_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "verdict receipt",
        )
    }

    pub fn insert_public_record(
        &mut self,
        record: FraudMarketPublicRecord,
    ) -> PrivateFraudEvidenceMarketResult<()> {
        insert_unique(
            &mut self.public_records,
            record.record_id.clone(),
            record,
            "public record",
        )
    }

    pub fn roots(&self) -> PrivateFraudEvidenceMarketRoots {
        PrivateFraudEvidenceMarketRoots {
            config_root: self.config.state_root(),
            authorization_root: private_fraud_evidence_market_collection_root(
                "AUTHORIZATIONS",
                self.authorizations
                    .values()
                    .map(PqReporterAuthorization::public_record)
                    .collect(),
            ),
            envelope_root: private_fraud_evidence_market_collection_root(
                "ENVELOPES",
                self.envelopes
                    .values()
                    .map(EncryptedEvidenceEnvelope::public_record)
                    .collect(),
            ),
            bounty_root: private_fraud_evidence_market_collection_root(
                "BOUNTIES",
                self.bounties
                    .values()
                    .map(ChallengeBounty::public_record)
                    .collect(),
            ),
            sponsorship_root: private_fraud_evidence_market_collection_root(
                "SPONSORSHIPS",
                self.sponsorships
                    .values()
                    .map(EvidenceSponsorship::public_record)
                    .collect(),
            ),
            disclosure_ticket_root: private_fraud_evidence_market_collection_root(
                "DISCLOSURE-TICKETS",
                self.disclosure_tickets
                    .values()
                    .map(PrivacySafeDisclosureTicket::public_record)
                    .collect(),
            ),
            verdict_receipt_root: private_fraud_evidence_market_collection_root(
                "VERDICT-RECEIPTS",
                self.verdict_receipts
                    .values()
                    .map(VerdictReceipt::public_record)
                    .collect(),
            ),
            public_record_root: private_fraud_evidence_market_collection_root(
                "PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(FraudMarketPublicRecord::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PrivateFraudEvidenceMarketCounters {
        PrivateFraudEvidenceMarketCounters {
            authorization_count: self.authorizations.len() as u64,
            active_authorization_count: self
                .authorizations
                .values()
                .filter(|authorization| {
                    authorization.status.usable() && authorization.expires_at_height >= self.height
                })
                .count() as u64,
            envelope_count: self.envelopes.len() as u64,
            open_envelope_count: self
                .envelopes
                .values()
                .filter(|envelope| !envelope.status.terminal())
                .count() as u64,
            high_severity_envelope_count: self
                .envelopes
                .values()
                .filter(|envelope| envelope.evidence_kind.high_severity())
                .count() as u64,
            bounty_count: self.bounties.len() as u64,
            open_bounty_count: self
                .bounties
                .values()
                .filter(|bounty| {
                    bounty.status.spendable() && bounty.expires_at_height >= self.height
                })
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            active_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| {
                    sponsorship.status.live() && sponsorship.expires_at_height >= self.height
                })
                .count() as u64,
            disclosure_ticket_count: self.disclosure_tickets.len() as u64,
            usable_disclosure_ticket_count: self
                .disclosure_tickets
                .values()
                .filter(|ticket| ticket.status.usable() && ticket.expires_at_height >= self.height)
                .count() as u64,
            verdict_receipt_count: self.verdict_receipts.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_bounty_units: self.bounties.values().fold(0_u64, |total, bounty| {
                total.saturating_add(bounty.bounty_units)
            }),
            total_sponsored_fee_units: self
                .sponsorships
                .values()
                .fold(0_u64, |total, sponsorship| {
                    total.saturating_add(sponsorship.sponsored_fee_units)
                }),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_fraud_evidence_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION,
            "schema_version": PRIVATE_FRAUD_EVIDENCE_MARKET_SCHEMA_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_fraud_evidence_market_record_root("STATE", &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateFraudEvidenceMarketResult<String> {
        self.config.validate()?;
        if self.authorizations.len() > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_AUTHORIZATIONS {
            return Err("authorization capacity exceeded".to_string());
        }
        if self.envelopes.len() > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_ENVELOPES {
            return Err("envelope capacity exceeded".to_string());
        }
        if self.bounties.len() > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_BOUNTIES {
            return Err("bounty capacity exceeded".to_string());
        }
        if self.sponsorships.len() > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_SPONSORSHIPS {
            return Err("sponsorship capacity exceeded".to_string());
        }
        if self.disclosure_tickets.len() > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_DISCLOSURE_TICKETS {
            return Err("disclosure ticket capacity exceeded".to_string());
        }
        if self.verdict_receipts.len() > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_VERDICT_RECEIPTS {
            return Err("verdict receipt capacity exceeded".to_string());
        }
        if self.public_records.len() > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_PUBLIC_RECORDS {
            return Err("public record capacity exceeded".to_string());
        }

        for (authorization_id, authorization) in &self.authorizations {
            if authorization_id != &authorization.authorization_id {
                return Err("authorization map key does not match id".to_string());
            }
            authorization.validate()?;
            if authorization.status.usable() && authorization.expires_at_height < self.height {
                return Err("active authorization expired before market height".to_string());
            }
            if authorization.stake_units < self.config.min_reporter_stake_units {
                return Err("authorization stake below configured minimum".to_string());
            }
        }

        for (envelope_id, envelope) in &self.envelopes {
            if envelope_id != &envelope.envelope_id {
                return Err("envelope map key does not match id".to_string());
            }
            envelope.validate()?;
            let authorization = self
                .authorizations
                .get(&envelope.authorization_id)
                .ok_or_else(|| "envelope references unknown authorization".to_string())?;
            if authorization.reporter_commitment != envelope.reporter_commitment {
                return Err("envelope reporter does not match authorization".to_string());
            }
            if !authorization.status.usable() {
                return Err("envelope authorization is not usable".to_string());
            }
            if envelope.privacy_set_size < self.config.min_privacy_set_size {
                return Err("envelope privacy set below configured minimum".to_string());
            }
            if envelope.disclosure_bps > self.config.max_disclosure_bps {
                return Err("envelope disclosure exceeds configured maximum".to_string());
            }
            if envelope.requested_bounty_units < self.config.min_bounty_units {
                return Err("envelope requested bounty below configured minimum".to_string());
            }
            if !envelope.status.terminal() && envelope.expires_at_height < self.height {
                return Err("active envelope expired before market height".to_string());
            }
        }

        for (bounty_id, bounty) in &self.bounties {
            if bounty_id != &bounty.bounty_id {
                return Err("bounty map key does not match id".to_string());
            }
            bounty.validate()?;
            if bounty.bounty_units < self.config.min_bounty_units {
                return Err("bounty below configured minimum".to_string());
            }
            if let Some(envelope_id) = &bounty.reserved_envelope_id {
                require_map_key("bounty reserved envelope", envelope_id, &self.envelopes)?;
            }
            if bounty.status.spendable() && bounty.expires_at_height < self.height {
                return Err("spendable bounty expired before market height".to_string());
            }
        }

        for (sponsorship_id, sponsorship) in &self.sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key does not match id".to_string());
            }
            sponsorship.validate()?;
            require_map_key(
                "sponsorship envelope",
                &sponsorship.envelope_id,
                &self.envelopes,
            )?;
            if sponsorship.sponsored_fee_units > self.config.sponsored_fee_units {
                return Err("sponsorship exceeds configured sponsored fee".to_string());
            }
            if sponsorship.status.live() && sponsorship.expires_at_height < self.height {
                return Err("live sponsorship expired before market height".to_string());
            }
        }

        for (ticket_id, ticket) in &self.disclosure_tickets {
            if ticket_id != &ticket.ticket_id {
                return Err("ticket map key does not match id".to_string());
            }
            ticket.validate()?;
            require_map_key("ticket envelope", &ticket.envelope_id, &self.envelopes)?;
            if ticket.disclosure_bps > self.config.max_disclosure_bps {
                return Err("ticket disclosure exceeds configured maximum".to_string());
            }
            if ticket.status.usable() && ticket.expires_at_height < self.height {
                return Err("usable ticket expired before market height".to_string());
            }
        }

        for (receipt_id, receipt) in &self.verdict_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("receipt map key does not match id".to_string());
            }
            receipt.validate()?;
            require_map_key("receipt envelope", &receipt.envelope_id, &self.envelopes)?;
            if let Some(bounty_id) = &receipt.bounty_id {
                require_map_key("receipt bounty", bounty_id, &self.bounties)?;
            }
            if let Some(ticket_id) = &receipt.ticket_id {
                require_map_key("receipt ticket", ticket_id, &self.disclosure_tickets)?;
            }
            if receipt.verifier_weight_bps < self.config.verdict_quorum_bps {
                return Err("receipt verifier weight below configured quorum".to_string());
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

pub fn private_fraud_evidence_market_account_commitment(account_label: &str) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-ACCOUNT",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_label),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-STRING",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_record_root(domain: &str, payload: &Value) -> String {
    private_fraud_evidence_market_payload_root(domain, payload)
}

pub fn private_fraud_evidence_market_state_root_from_record(record: &Value) -> String {
    private_fraud_evidence_market_record_root("STATE", record)
}

pub fn private_fraud_evidence_market_collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("PRIVATE-FRAUD-EVIDENCE-MARKET-{domain}"), &records)
}

pub fn private_fraud_evidence_market_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-FRAUD-EVIDENCE-MARKET-{domain}"), &leaves)
}

pub fn private_fraud_evidence_market_authorization_id(
    reporter_commitment: &str,
    pq_public_key_commitment: &str,
    scope_root: &str,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-AUTHORIZATION-ID",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reporter_commitment),
            HashPart::Str(pq_public_key_commitment),
            HashPart::Str(scope_root),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_envelope_id(
    authorization_id: &str,
    fraud_domain: FraudDomain,
    evidence_kind: &FraudEvidenceKind,
    subject_id: &str,
    encrypted_payload_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-ENVELOPE-ID",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(authorization_id),
            HashPart::Str(fraud_domain.as_str()),
            HashPart::Str(&evidence_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_fraud_evidence_market_bounty_id(
    sponsor_commitment: &str,
    fraud_domain: FraudDomain,
    evidence_kind: &FraudEvidenceKind,
    subject_id: &str,
    bounty_units: u64,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-BOUNTY-ID",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fraud_domain.as_str()),
            HashPart::Str(&evidence_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(bounty_units as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_sponsorship_id(
    envelope_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    sponsored_fee_units: u64,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-SPONSORSHIP-ID",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_disclosure_ticket_id(
    envelope_id: &str,
    requester_commitment: &str,
    purpose_root: &str,
    disclosure_bps: u64,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-DISCLOSURE-TICKET-ID",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(purpose_root),
            HashPart::Int(disclosure_bps as i128),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_verdict_receipt_id(
    envelope_id: &str,
    outcome: VerdictOutcome,
    adjudicator_commitment: &str,
    verdict_root: &str,
    decided_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-VERDICT-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(envelope_id),
            HashPart::Str(outcome.as_str()),
            HashPart::Str(adjudicator_commitment),
            HashPart::Str(verdict_root),
            HashPart::Int(decided_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_fraud_evidence_market_public_record_id(
    subject_id: &str,
    record_kind: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-FRAUD-EVIDENCE-MARKET-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PRIVATE_FRAUD_EVIDENCE_MARKET_PROTOCOL_VERSION),
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

fn ensure_non_empty(value: &str, label: &str) -> PrivateFraudEvidenceMarketResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateFraudEvidenceMarketResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateFraudEvidenceMarketResult<()> {
    if value > PRIVATE_FRAUD_EVIDENCE_MARKET_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_distinct_strings(values: &[String], label: &str) -> PrivateFraudEvidenceMarketResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> PrivateFraudEvidenceMarketResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    ensure_distinct_strings(values, label)
}

fn validate_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> PrivateFraudEvidenceMarketResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn require_map_key<T>(
    label: &str,
    key: &str,
    map: &BTreeMap<String, T>,
) -> PrivateFraudEvidenceMarketResult<()> {
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
) -> PrivateFraudEvidenceMarketResult<()> {
    if map.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    map.insert(id, record);
    Ok(())
}
