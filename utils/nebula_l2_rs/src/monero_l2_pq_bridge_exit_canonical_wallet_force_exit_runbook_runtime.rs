use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalWalletForceExitRunbookRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_FORCE_EXIT_RUNBOOK_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-wallet-force-exit-runbook-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_FORCE_EXIT_RUNBOOK_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RUNBOOK_SUITE: &str = "monero-l2-pq-bridge-canonical-wallet-force-exit-runbook-v1";
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_FINALITY_BLOCKS: u64 = 40;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u64 = 30_000_000;
pub const DEFAULT_MIN_RECEIPT_SHARDS: u16 = 2;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u16 = 2;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_BLOCKERS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookStatus {
    Ready,
    WaitingChallengeWindow,
    Releasable,
    EmergencyFeePath,
    Blocked,
}

impl RunbookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::WaitingChallengeWindow => "waiting_challenge_window",
            Self::Releasable => "releasable",
            Self::EmergencyFeePath => "emergency_fee_path",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorMisbehavior {
    WithheldRelease,
    InvalidExitBatch,
    MissingReceiptShard,
    CensoredForcedExit,
    OverchargedExitFee,
    StaleStateRoot,
}

impl OperatorMisbehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WithheldRelease => "withheld_release",
            Self::InvalidExitBatch => "invalid_exit_batch",
            Self::MissingReceiptShard => "missing_receipt_shard",
            Self::CensoredForcedExit => "censored_forced_exit",
            Self::OverchargedExitFee => "overcharged_exit_fee",
            Self::StaleStateRoot => "stale_state_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DepositCommitment,
    ReconstructionVector,
    ReceiptShard,
    CanonicalTranscriptAnchor,
    OperatorSignature,
    DevnetFixture,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositCommitment => "deposit_commitment",
            Self::ReconstructionVector => "reconstruction_vector",
            Self::ReceiptShard => "receipt_shard",
            Self::CanonicalTranscriptAnchor => "canonical_transcript_anchor",
            Self::OperatorSignature => "operator_signature",
            Self::DevnetFixture => "devnet_fixture",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptReconstructionStatus {
    Complete,
    ThresholdRecovered,
    NeedsWalletBackup,
    MissingShard,
}

impl ReceiptReconstructionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ThresholdRecovered => "threshold_recovered",
            Self::NeedsWalletBackup => "needs_wallet_backup",
            Self::MissingShard => "missing_shard",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipProofMode {
    NoteCommitment,
    NullifierCommitment,
    KeyImageBinding,
    PqWalletAuthorization,
}

impl OwnershipProofMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoteCommitment => "note_commitment",
            Self::NullifierCommitment => "nullifier_commitment",
            Self::KeyImageBinding => "key_image_binding",
            Self::PqWalletAuthorization => "pq_wallet_authorization",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAuthorizationStatus {
    PendingChallengeWindow,
    Authorized,
    DeniedByChallenge,
    MissingQuorum,
}

impl ReleaseAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingChallengeWindow => "pending_challenge_window",
            Self::Authorized => "authorized",
            Self::DeniedByChallenge => "denied_by_challenge",
            Self::MissingQuorum => "missing_quorum",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserFacingBlocker {
    DepositEvidenceUnavailable,
    ReconstructionVectorUnavailable,
    ReceiptDecryptionUnavailable,
    OwnershipProofWouldLeakMetadata,
    NullifierAlreadySpent,
    ChallengeWindowOpen,
    ReleaseAuthorizationMissing,
    EmergencyFeeTooHigh,
    DevnetDataMismatch,
}

impl UserFacingBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositEvidenceUnavailable => "deposit_evidence_unavailable",
            Self::ReconstructionVectorUnavailable => "reconstruction_vector_unavailable",
            Self::ReceiptDecryptionUnavailable => "receipt_decryption_unavailable",
            Self::OwnershipProofWouldLeakMetadata => "ownership_proof_would_leak_metadata",
            Self::NullifierAlreadySpent => "nullifier_already_spent",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ReleaseAuthorizationMissing => "release_authorization_missing",
            Self::EmergencyFeeTooHigh => "emergency_fee_too_high",
            Self::DevnetDataMismatch => "devnet_data_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub runbook_suite: String,
    pub challenge_window_blocks: u64,
    pub release_finality_blocks: u64,
    pub low_fee_cap_atomic: u64,
    pub min_receipt_shards: u16,
    pub min_privacy_set_size: u64,
    pub max_metadata_leakage_units: u16,
    pub min_pq_security_bits: u16,
    pub max_user_blockers: usize,
    pub require_devnet_data: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            runbook_suite: RUNBOOK_SUITE.to_string(),
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_finality_blocks: DEFAULT_RELEASE_FINALITY_BLOCKS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            min_receipt_shards: DEFAULT_MIN_RECEIPT_SHARDS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_blockers: DEFAULT_MAX_USER_BLOCKERS,
            require_devnet_data: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "runbook_suite": self.runbook_suite,
            "challenge_window_blocks": self.challenge_window_blocks,
            "release_finality_blocks": self.release_finality_blocks,
            "low_fee_cap_atomic": self.low_fee_cap_atomic,
            "min_receipt_shards": self.min_receipt_shards,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_blockers": self.max_user_blockers,
            "require_devnet_data": self.require_devnet_data,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-RUNBOOK-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceLocator {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub deposit_id: String,
    pub vector_id: String,
    pub source: String,
    pub commitment_root: String,
    pub transcript_root: String,
    pub observed_at_height: u64,
}

impl EvidenceLocator {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "deposit_id": self.deposit_id,
            "vector_id": self.vector_id,
            "source": self.source,
            "commitment_root": self.commitment_root,
            "transcript_root": self.transcript_root,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-EVIDENCE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptReconstruction {
    pub receipt_id: String,
    pub status: ReceiptReconstructionStatus,
    pub encrypted_receipt_root: String,
    pub decrypted_receipt_commitment: String,
    pub shard_root: String,
    pub shard_count: u16,
    pub recovery_hint_root: String,
    pub metadata_redaction_root: String,
}

impl ReceiptReconstruction {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "decrypted_receipt_commitment": self.decrypted_receipt_commitment,
            "shard_root": self.shard_root,
            "shard_count": self.shard_count,
            "recovery_hint_root": self.recovery_hint_root,
            "metadata_redaction_root": self.metadata_redaction_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-RECEIPT-RECONSTRUCTION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OwnershipProof {
    pub proof_id: String,
    pub mode: OwnershipProofMode,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub wallet_authority_root: String,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u16,
    pub pq_security_bits: u16,
}

impl OwnershipProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "mode": self.mode.as_str(),
            "note_commitment_root": self.note_commitment_root,
            "nullifier_root": self.nullifier_root,
            "wallet_authority_root": self.wallet_authority_root,
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-OWNERSHIP-PROOF",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitClaim {
    pub claim_id: String,
    pub wallet_route_id: String,
    pub deposit_root: String,
    pub vector_root: String,
    pub receipt_root: String,
    pub ownership_proof_root: String,
    pub destination_commitment_root: String,
    pub amount_commitment_root: String,
    pub claim_opened_at_height: u64,
}

impl ForcedExitClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "wallet_route_id": self.wallet_route_id,
            "deposit_root": self.deposit_root,
            "vector_root": self.vector_root,
            "receipt_root": self.receipt_root,
            "ownership_proof_root": self.ownership_proof_root,
            "destination_commitment_root": self.destination_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "claim_opened_at_height": self.claim_opened_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-CLAIM",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeWindow {
    pub window_id: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub observed_height: u64,
    pub challenge_root: String,
    pub settlement_root: String,
}

impl ChallengeWindow {
    pub fn is_closed(&self) -> bool {
        self.observed_height >= self.closes_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "observed_height": self.observed_height,
            "challenge_root": self.challenge_root,
            "settlement_root": self.settlement_root,
            "closed": self.is_closed(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-CHALLENGE-WINDOW",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseAuthorization {
    pub authorization_id: String,
    pub status: ReleaseAuthorizationStatus,
    pub release_root: String,
    pub authority_quorum_root: String,
    pub monero_release_tx_commitment: String,
    pub finality_height: u64,
}

impl ReleaseAuthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "status": self.status.as_str(),
            "release_root": self.release_root,
            "authority_quorum_root": self.authority_quorum_root,
            "monero_release_tx_commitment": self.monero_release_tx_commitment,
            "finality_height": self.finality_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-RELEASE-AUTHORIZATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmergencyFeePath {
    pub path_id: String,
    pub sponsor_commitment_root: String,
    pub fee_quote_root: String,
    pub max_fee_atomic: u64,
    pub observed_fee_atomic: u64,
    pub fallback_batch_root: String,
    pub relay_policy_root: String,
}

impl EmergencyFeePath {
    pub fn within_cap(&self) -> bool {
        self.observed_fee_atomic <= self.max_fee_atomic
    }

    pub fn public_record(&self) -> Value {
        json!({
            "path_id": self.path_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "fee_quote_root": self.fee_quote_root,
            "max_fee_atomic": self.max_fee_atomic,
            "observed_fee_atomic": self.observed_fee_atomic,
            "fallback_batch_root": self.fallback_batch_root,
            "relay_policy_root": self.relay_policy_root,
            "within_cap": self.within_cap(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-EMERGENCY-FEE-PATH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DevnetData {
    pub network: String,
    pub faucet_deposit_txid: String,
    pub canonical_transcript_root: String,
    pub operator_set_root: String,
    pub wallet_fixture_root: String,
    pub monero_devnet_height: u64,
    pub l2_devnet_height: u64,
}

impl DevnetData {
    pub fn public_record(&self) -> Value {
        json!({
            "network": self.network,
            "faucet_deposit_txid": self.faucet_deposit_txid,
            "canonical_transcript_root": self.canonical_transcript_root,
            "operator_set_root": self.operator_set_root,
            "wallet_fixture_root": self.wallet_fixture_root,
            "monero_devnet_height": self.monero_devnet_height,
            "l2_devnet_height": self.l2_devnet_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-DEVNET-DATA",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockerRecord {
    pub blocker: UserFacingBlocker,
    pub label: String,
    pub user_action: String,
    pub evidence_root: String,
}

impl BlockerRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker": self.blocker.as_str(),
            "label": self.label,
            "user_action": self.user_action,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-BLOCKER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub status: RunbookStatus,
    pub misbehavior: OperatorMisbehavior,
    pub evidence: Vec<EvidenceLocator>,
    pub receipt: ReceiptReconstruction,
    pub ownership_proof: OwnershipProof,
    pub claim: ForcedExitClaim,
    pub challenge_window: ChallengeWindow,
    pub release_authorization: ReleaseAuthorization,
    pub emergency_fee_path: EmergencyFeePath,
    pub blockers: Vec<BlockerRecord>,
    pub devnet_data: DevnetData,
    pub roots: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let seed_root = runbook_seed_root("devnet-wallet-force-exit-runbook");
        let deposit_root = labeled_root("deposit", &seed_root);
        let vector_root = labeled_root("reconstruction-vector", &seed_root);
        let transcript_root = labeled_root("canonical-transcript", &seed_root);
        let receipt_shard_root = labeled_root("receipt-shards", &seed_root);
        let redaction_root = labeled_root("redaction-policy", &seed_root);
        let ownership_note_root = labeled_root("note-commitment", &seed_root);
        let ownership_nullifier_root = labeled_root("nullifier", &seed_root);
        let wallet_authority_root = labeled_root("wallet-authority", &seed_root);
        let release_root = labeled_root("release", &seed_root);
        let quorum_root = labeled_root("authority-quorum", &seed_root);
        let devnet_fixture_root = labeled_root("devnet-fixture", &seed_root);

        let evidence = vec![
            EvidenceLocator {
                evidence_id: "evidence-deposit-devnet-001".to_string(),
                kind: EvidenceKind::DepositCommitment,
                deposit_id: "deposit-devnet-wallet-force-exit-001".to_string(),
                vector_id: "vector-devnet-wallet-force-exit-001".to_string(),
                source: "wallet_local_index_and_l2_deposit_tree".to_string(),
                commitment_root: deposit_root.clone(),
                transcript_root: transcript_root.clone(),
                observed_at_height: 42_000,
            },
            EvidenceLocator {
                evidence_id: "evidence-vector-devnet-001".to_string(),
                kind: EvidenceKind::ReconstructionVector,
                deposit_id: "deposit-devnet-wallet-force-exit-001".to_string(),
                vector_id: "vector-devnet-wallet-force-exit-001".to_string(),
                source: "canonical_exit_reconstruction_vector_registry".to_string(),
                commitment_root: vector_root.clone(),
                transcript_root: transcript_root.clone(),
                observed_at_height: 42_001,
            },
            EvidenceLocator {
                evidence_id: "evidence-receipt-shards-devnet-001".to_string(),
                kind: EvidenceKind::ReceiptShard,
                deposit_id: "deposit-devnet-wallet-force-exit-001".to_string(),
                vector_id: "vector-devnet-wallet-force-exit-001".to_string(),
                source: "wallet_backup_and_da_receipt_lane".to_string(),
                commitment_root: receipt_shard_root.clone(),
                transcript_root: transcript_root.clone(),
                observed_at_height: 42_002,
            },
        ];

        let receipt = ReceiptReconstruction {
            receipt_id: "receipt-devnet-wallet-force-exit-001".to_string(),
            status: ReceiptReconstructionStatus::ThresholdRecovered,
            encrypted_receipt_root: labeled_root("encrypted-receipt", &seed_root),
            decrypted_receipt_commitment: labeled_root("decrypted-receipt-commitment", &seed_root),
            shard_root: receipt_shard_root,
            shard_count: config.min_receipt_shards,
            recovery_hint_root: labeled_root("wallet-recovery-hints", &seed_root),
            metadata_redaction_root: redaction_root,
        };

        let ownership_proof = OwnershipProof {
            proof_id: "ownership-proof-devnet-wallet-force-exit-001".to_string(),
            mode: OwnershipProofMode::PqWalletAuthorization,
            note_commitment_root: ownership_note_root,
            nullifier_root: ownership_nullifier_root,
            wallet_authority_root,
            privacy_set_size: config.min_privacy_set_size,
            metadata_leakage_units: 0,
            pq_security_bits: config.min_pq_security_bits,
        };

        let claim = ForcedExitClaim {
            claim_id: "forced-exit-claim-devnet-wallet-001".to_string(),
            wallet_route_id: "canonical-wallet-force-exit-route".to_string(),
            deposit_root: deposit_root.clone(),
            vector_root: vector_root.clone(),
            receipt_root: receipt.root(),
            ownership_proof_root: ownership_proof.root(),
            destination_commitment_root: labeled_root("destination-commitment", &seed_root),
            amount_commitment_root: labeled_root("amount-commitment", &seed_root),
            claim_opened_at_height: 42_010,
        };

        let challenge_window = ChallengeWindow {
            window_id: "challenge-window-devnet-wallet-force-exit-001".to_string(),
            opened_at_height: claim.claim_opened_at_height,
            closes_at_height: claim.claim_opened_at_height + config.challenge_window_blocks,
            observed_height: claim.claim_opened_at_height + config.challenge_window_blocks,
            challenge_root: merkle_root("WALLET-FORCE-EXIT-EMPTY-CHALLENGES", &[]),
            settlement_root: labeled_root("challenge-settlement", &seed_root),
        };

        let release_authorization = ReleaseAuthorization {
            authorization_id: "release-authorization-devnet-wallet-001".to_string(),
            status: ReleaseAuthorizationStatus::Authorized,
            release_root,
            authority_quorum_root: quorum_root,
            monero_release_tx_commitment: labeled_root("monero-release-tx", &seed_root),
            finality_height: challenge_window.closes_at_height + config.release_finality_blocks,
        };

        let emergency_fee_path = EmergencyFeePath {
            path_id: "low-fee-emergency-path-devnet-001".to_string(),
            sponsor_commitment_root: labeled_root("sponsor-commitment", &seed_root),
            fee_quote_root: labeled_root("fee-quote", &seed_root),
            max_fee_atomic: config.low_fee_cap_atomic,
            observed_fee_atomic: config.low_fee_cap_atomic / 2,
            fallback_batch_root: labeled_root("fallback-batch", &seed_root),
            relay_policy_root: labeled_root("relay-policy", &seed_root),
        };

        let devnet_data = DevnetData {
            network: "monero-l2-devnet".to_string(),
            faucet_deposit_txid: "devnet-faucet-deposit-force-exit-001".to_string(),
            canonical_transcript_root: transcript_root,
            operator_set_root: labeled_root("operator-set", &seed_root),
            wallet_fixture_root: devnet_fixture_root,
            monero_devnet_height: 1_024,
            l2_devnet_height: 42_740,
        };

        let blockers = derive_blockers(
            &config,
            &evidence,
            &receipt,
            &ownership_proof,
            &challenge_window,
            &release_authorization,
            &emergency_fee_path,
            &devnet_data,
        );

        let status = derive_status(
            &blockers,
            &challenge_window,
            &release_authorization,
            &emergency_fee_path,
        );

        let mut state = Self {
            config,
            status,
            misbehavior: OperatorMisbehavior::WithheldRelease,
            evidence,
            receipt,
            ownership_proof,
            claim,
            challenge_window,
            release_authorization,
            emergency_fee_path,
            blockers,
            devnet_data,
            roots: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "status": self.status.as_str(),
            "misbehavior": self.misbehavior.as_str(),
            "evidence": self.evidence.iter().map(EvidenceLocator::public_record).collect::<Vec<_>>(),
            "receipt": self.receipt.public_record(),
            "ownership_proof": self.ownership_proof.public_record(),
            "claim": self.claim.public_record(),
            "challenge_window": self.challenge_window.public_record(),
            "release_authorization": self.release_authorization.public_record(),
            "emergency_fee_path": self.emergency_fee_path.public_record(),
            "blockers": self.blockers.iter().map(BlockerRecord::public_record).collect::<Vec<_>>(),
            "devnet_data": self.devnet_data.public_record(),
            "roots": self.roots,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-RUNBOOK-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(self.misbehavior.as_str()),
                HashPart::Str(&self.config.root()),
                HashPart::Str(&self.evidence_root()),
                HashPart::Str(&self.receipt.root()),
                HashPart::Str(&self.ownership_proof.root()),
                HashPart::Str(&self.claim.root()),
                HashPart::Str(&self.challenge_window.root()),
                HashPart::Str(&self.release_authorization.root()),
                HashPart::Str(&self.emergency_fee_path.root()),
                HashPart::Str(&self.blocker_root()),
                HashPart::Str(&self.devnet_data.root()),
            ],
            32,
        )
    }

    pub fn evidence_root(&self) -> String {
        merkle_root(
            "WALLET-FORCE-EXIT-EVIDENCE-ROOT",
            &self
                .evidence
                .iter()
                .map(EvidenceLocator::root)
                .collect::<Vec<_>>(),
        )
    }

    pub fn blocker_root(&self) -> String {
        merkle_root(
            "WALLET-FORCE-EXIT-BLOCKER-ROOT",
            &self
                .blockers
                .iter()
                .map(BlockerRecord::root)
                .collect::<Vec<_>>(),
        )
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = BTreeMap::new();
        roots.insert("config_root".to_string(), self.config.root());
        roots.insert("evidence_root".to_string(), self.evidence_root());
        roots.insert("receipt_root".to_string(), self.receipt.root());
        roots.insert(
            "ownership_proof_root".to_string(),
            self.ownership_proof.root(),
        );
        roots.insert("claim_root".to_string(), self.claim.root());
        roots.insert(
            "challenge_window_root".to_string(),
            self.challenge_window.root(),
        );
        roots.insert(
            "release_authorization_root".to_string(),
            self.release_authorization.root(),
        );
        roots.insert(
            "emergency_fee_path_root".to_string(),
            self.emergency_fee_path.root(),
        );
        roots.insert("blocker_root".to_string(), self.blocker_root());
        roots.insert("devnet_data_root".to_string(), self.devnet_data.root());
        roots.insert(
            "state_root".to_string(),
            self.state_root_without_roots(&roots),
        );
        self.roots = roots;
    }

    pub fn locate_deposit_and_vector_evidence(&self) -> Result<Vec<EvidenceLocator>> {
        if self.evidence.is_empty() {
            return Err("deposit and reconstruction-vector evidence are unavailable".to_string());
        }
        Ok(self.evidence.clone())
    }

    pub fn reconstruct_encrypted_receipt_data(&self) -> Result<ReceiptReconstruction> {
        if self.receipt.shard_count < self.config.min_receipt_shards {
            return Err("receipt shard threshold is below the configured minimum".to_string());
        }
        if matches!(
            self.receipt.status,
            ReceiptReconstructionStatus::MissingShard
        ) {
            return Err(
                "encrypted receipt data cannot be reconstructed from available shards".to_string(),
            );
        }
        Ok(self.receipt.clone())
    }

    pub fn prove_note_and_nullifier_ownership(&self) -> Result<OwnershipProof> {
        if self.ownership_proof.privacy_set_size < self.config.min_privacy_set_size {
            return Err("ownership proof privacy set is below the configured floor".to_string());
        }
        if self.ownership_proof.metadata_leakage_units > self.config.max_metadata_leakage_units {
            return Err("ownership proof exceeds the metadata leakage budget".to_string());
        }
        if self.ownership_proof.pq_security_bits < self.config.min_pq_security_bits {
            return Err(
                "post-quantum wallet authorization is below the configured security floor"
                    .to_string(),
            );
        }
        Ok(self.ownership_proof.clone())
    }

    pub fn build_forced_exit_claim(&self) -> Result<ForcedExitClaim> {
        self.locate_deposit_and_vector_evidence()?;
        self.reconstruct_encrypted_receipt_data()?;
        self.prove_note_and_nullifier_ownership()?;
        Ok(self.claim.clone())
    }

    pub fn wait_challenge_window(&self, observed_height: u64) -> Result<ChallengeWindow> {
        if observed_height < self.challenge_window.closes_at_height {
            return Err(format!(
                "challenge window remains open until height {}",
                self.challenge_window.closes_at_height
            ));
        }
        Ok(self.challenge_window.clone())
    }

    pub fn verify_release_authorization(&self) -> Result<ReleaseAuthorization> {
        if !matches!(
            self.release_authorization.status,
            ReleaseAuthorizationStatus::Authorized
        ) {
            return Err(
                "release authorization is not approved by the authority quorum".to_string(),
            );
        }
        if !self.challenge_window.is_closed() {
            return Err(
                "release authorization cannot settle before the challenge window closes"
                    .to_string(),
            );
        }
        Ok(self.release_authorization.clone())
    }

    pub fn enforce_low_fee_emergency_path(&self) -> Result<EmergencyFeePath> {
        if !self.emergency_fee_path.within_cap() {
            return Err("emergency exit fee exceeds the configured low-fee cap".to_string());
        }
        Ok(self.emergency_fee_path.clone())
    }

    pub fn user_facing_blockers(&self) -> Vec<BlockerRecord> {
        self.blockers.clone()
    }

    fn state_root_without_roots(&self, roots: &BTreeMap<String, String>) -> String {
        domain_hash(
            "WALLET-FORCE-EXIT-RUNBOOK-STATE-ROOTS",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&json!(roots)),
                HashPart::Json(&json!(self
                    .blockers
                    .iter()
                    .map(BlockerRecord::public_record)
                    .collect::<Vec<_>>())),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn runbook_seed_root(seed: &str) -> String {
    domain_hash(
        "WALLET-FORCE-EXIT-RUNBOOK-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn labeled_root(label: &str, seed_root: &str) -> String {
    domain_hash(
        "WALLET-FORCE-EXIT-RUNBOOK-LABELED-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(seed_root),
        ],
        32,
    )
}

pub fn derive_blockers(
    config: &Config,
    evidence: &[EvidenceLocator],
    receipt: &ReceiptReconstruction,
    ownership_proof: &OwnershipProof,
    challenge_window: &ChallengeWindow,
    release_authorization: &ReleaseAuthorization,
    emergency_fee_path: &EmergencyFeePath,
    devnet_data: &DevnetData,
) -> Vec<BlockerRecord> {
    let mut blockers = Vec::new();
    let evidence_root = merkle_root(
        "WALLET-FORCE-EXIT-DERIVED-EVIDENCE",
        &evidence
            .iter()
            .map(EvidenceLocator::root)
            .collect::<Vec<_>>(),
    );

    if evidence.is_empty() {
        blockers.push(blocker(
            UserFacingBlocker::DepositEvidenceUnavailable,
            "Deposit evidence is not indexed",
            "Rescan the wallet bridge index or import the deposit proof bundle.",
            &evidence_root,
        ));
    }
    if !evidence
        .iter()
        .any(|entry| entry.kind == EvidenceKind::ReconstructionVector)
    {
        blockers.push(blocker(
            UserFacingBlocker::ReconstructionVectorUnavailable,
            "Canonical reconstruction vector is missing",
            "Fetch the vector from the canonical transcript mirror.",
            &evidence_root,
        ));
    }
    if receipt.shard_count < config.min_receipt_shards
        || matches!(receipt.status, ReceiptReconstructionStatus::MissingShard)
    {
        blockers.push(blocker(
            UserFacingBlocker::ReceiptDecryptionUnavailable,
            "Receipt data is below recovery threshold",
            "Restore the wallet backup or wait for another receipt shard.",
            &receipt.root(),
        ));
    }
    if ownership_proof.privacy_set_size < config.min_privacy_set_size
        || ownership_proof.metadata_leakage_units > config.max_metadata_leakage_units
    {
        blockers.push(blocker(
            UserFacingBlocker::OwnershipProofWouldLeakMetadata,
            "Ownership proof would reveal private metadata",
            "Use a larger privacy set or a stronger redaction route.",
            &ownership_proof.root(),
        ));
    }
    if !challenge_window.is_closed() {
        blockers.push(blocker(
            UserFacingBlocker::ChallengeWindowOpen,
            "Challenge window is still open",
            "Wait until the force-exit challenge window closes.",
            &challenge_window.root(),
        ));
    }
    if !matches!(
        release_authorization.status,
        ReleaseAuthorizationStatus::Authorized
    ) {
        blockers.push(blocker(
            UserFacingBlocker::ReleaseAuthorizationMissing,
            "Release authorization is not yet approved",
            "Wait for the authority quorum release record.",
            &release_authorization.root(),
        ));
    }
    if !emergency_fee_path.within_cap() {
        blockers.push(blocker(
            UserFacingBlocker::EmergencyFeeTooHigh,
            "Emergency relay fee exceeds the user cap",
            "Use the sponsored low-fee batch or wait for fee relief.",
            &emergency_fee_path.root(),
        ));
    }
    if config.require_devnet_data && devnet_data.wallet_fixture_root.is_empty() {
        blockers.push(blocker(
            UserFacingBlocker::DevnetDataMismatch,
            "Devnet wallet fixture data is missing",
            "Refresh the devnet fixture bundle before rehearsing release.",
            &devnet_data.root(),
        ));
    }

    blockers.truncate(config.max_user_blockers);
    blockers
}

pub fn derive_status(
    blockers: &[BlockerRecord],
    challenge_window: &ChallengeWindow,
    release_authorization: &ReleaseAuthorization,
    emergency_fee_path: &EmergencyFeePath,
) -> RunbookStatus {
    if !blockers.is_empty() {
        return RunbookStatus::Blocked;
    }
    if !challenge_window.is_closed() {
        return RunbookStatus::WaitingChallengeWindow;
    }
    if !emergency_fee_path.within_cap() {
        return RunbookStatus::EmergencyFeePath;
    }
    if matches!(
        release_authorization.status,
        ReleaseAuthorizationStatus::Authorized
    ) {
        return RunbookStatus::Releasable;
    }
    RunbookStatus::Ready
}

pub fn blocker(
    blocker: UserFacingBlocker,
    label: &str,
    user_action: &str,
    evidence_root: &str,
) -> BlockerRecord {
    BlockerRecord {
        blocker,
        label: label.to_string(),
        user_action: user_action.to_string(),
        evidence_root: evidence_root.to_string(),
    }
}
