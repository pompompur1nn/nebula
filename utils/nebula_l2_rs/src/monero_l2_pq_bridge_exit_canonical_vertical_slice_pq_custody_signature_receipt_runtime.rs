use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePqCustodySignatureReceiptRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_CUSTODY_SIGNATURE_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-custody-signature-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_CUSTODY_SIGNATURE_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_SUITE: &str = "monero-l2-pq-custody-signature-receipt-deterministic-evidence-v1";
pub const SIGNATURE_DOMAIN_SUITE: &str = "monero-l2-pq-custody-signature-domain-root-v1";
pub const WATCHER_ATTESTATION_SUITE: &str = "monero-l2-pq-custody-signature-watcher-attestation-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_AUTHORITY_EPOCH: u64 = 73;
pub const DEFAULT_L2_HEIGHT: u64 = 884_360;
pub const DEFAULT_MONERO_HEIGHT: u64 = 2_771_560;
pub const DEFAULT_MIN_SIGNER_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MIN_COMBINED_WEIGHT_BPS: u16 = 7_500;
pub const DEFAULT_MIN_SIGNER_COUNT: u16 = 3;
pub const DEFAULT_MIN_WATCHER_COUNT: u16 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ROTATION_GRACE_BLOCKS: u64 = 72;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsaShake,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsaShake => "hybrid_ml_dsa_slh_dsa_shake",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureDomainKind {
    CustodyAuthorization,
    ForcedExitClaim,
    WithdrawalRelease,
    RotationAcknowledgement,
}

impl SignatureDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyAuthorization => "custody_authorization",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::WithdrawalRelease => "withdrawal_release",
            Self::RotationAcknowledgement => "rotation_acknowledgement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    CustodyCouncil,
    WithdrawalCouncil,
    ReserveCouncil,
    EmergencyCouncil,
}

impl SignerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyCouncil => "custody_council",
            Self::WithdrawalCouncil => "withdrawal_council",
            Self::ReserveCouncil => "reserve_council",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherKind {
    MoneroLock,
    L2Burn,
    ChallengeWindow,
    SettlementReceipt,
    ReserveProof,
}

impl WatcherKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroLock => "monero_lock",
            Self::L2Burn => "l2_burn",
            Self::ChallengeWindow => "challenge_window",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ReserveProof => "reserve_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Active,
    Grace,
    Scheduled,
    Retired,
    Revoked,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Scheduled => "scheduled",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn permits_signature(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Signed,
    Held,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Held => "held",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    MissingSignerQuorum,
    MissingWatcherAttestation,
    SignerWeightShortfall,
    WatcherWeightShortfall,
    CombinedWeightShortfall,
    SignatureDomainMismatch,
    KeyEpochMismatch,
    RotationNotActive,
    WithdrawalAuthorityMismatch,
    TranscriptRootMismatch,
    ReceiptExpired,
    DuplicateSigner,
    DuplicateWatcher,
}

impl HoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingSignerQuorum => "missing_signer_quorum",
            Self::MissingWatcherAttestation => "missing_watcher_attestation",
            Self::SignerWeightShortfall => "signer_weight_shortfall",
            Self::WatcherWeightShortfall => "watcher_weight_shortfall",
            Self::CombinedWeightShortfall => "combined_weight_shortfall",
            Self::SignatureDomainMismatch => "signature_domain_mismatch",
            Self::KeyEpochMismatch => "key_epoch_mismatch",
            Self::RotationNotActive => "rotation_not_active",
            Self::WithdrawalAuthorityMismatch => "withdrawal_authority_mismatch",
            Self::TranscriptRootMismatch => "transcript_root_mismatch",
            Self::ReceiptExpired => "receipt_expired",
            Self::DuplicateSigner => "duplicate_signer",
            Self::DuplicateWatcher => "duplicate_watcher",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_suite: String,
    pub signature_domain_suite: String,
    pub watcher_attestation_suite: String,
    pub vertical_slice_id: String,
    pub authority_epoch: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_signer_weight_bps: u16,
    pub min_watcher_weight_bps: u16,
    pub min_combined_weight_bps: u16,
    pub min_signer_count: u16,
    pub min_watcher_count: u16,
    pub min_pq_security_bits: u16,
    pub receipt_ttl_blocks: u64,
    pub rotation_grace_blocks: u64,
    pub fail_closed_on_any_hold: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            signature_domain_suite: SIGNATURE_DOMAIN_SUITE.to_string(),
            watcher_attestation_suite: WATCHER_ATTESTATION_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            authority_epoch: DEFAULT_AUTHORITY_EPOCH,
            l2_height: DEFAULT_L2_HEIGHT,
            monero_height: DEFAULT_MONERO_HEIGHT,
            min_signer_weight_bps: DEFAULT_MIN_SIGNER_WEIGHT_BPS,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            min_combined_weight_bps: DEFAULT_MIN_COMBINED_WEIGHT_BPS,
            min_signer_count: DEFAULT_MIN_SIGNER_COUNT,
            min_watcher_count: DEFAULT_MIN_WATCHER_COUNT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            rotation_grace_blocks: DEFAULT_ROTATION_GRACE_BLOCKS,
            fail_closed_on_any_hold: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json_record(self)
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureDomainRoot {
    pub domain_id: String,
    pub kind: SignatureDomainKind,
    pub scheme: PqSignatureScheme,
    pub authority_epoch: u64,
    pub withdrawal_authority_root: String,
    pub transcript_root: String,
    pub challenge_window_root: String,
    pub domain_root: String,
}

impl SignatureDomainRoot {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyEpochReceipt {
    pub epoch_id: String,
    pub epoch_number: u64,
    pub previous_epoch_root: String,
    pub signer_set_root: String,
    pub watcher_set_root: String,
    pub withdrawal_authority_root: String,
    pub starts_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub receipt_root: String,
}

impl KeyEpochReceipt {
    pub fn active_at(&self, height: u64) -> bool {
        self.starts_at_l2_height <= height && height <= self.expires_at_l2_height
    }

    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerWeight {
    pub signer_id: String,
    pub role: SignerRole,
    pub weight_bps: u16,
    pub pq_security_bits: u16,
    pub active_from_l2_height: u64,
    pub active_until_l2_height: u64,
    pub signer_root: String,
}

impl SignerWeight {
    pub fn active_at(&self, height: u64) -> bool {
        self.active_from_l2_height <= height && height <= self.active_until_l2_height
    }

    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherWeight {
    pub watcher_id: String,
    pub kind: WatcherKind,
    pub weight_bps: u16,
    pub pq_security_bits: u16,
    pub active_from_l2_height: u64,
    pub active_until_l2_height: u64,
    pub watcher_root: String,
}

impl WatcherWeight {
    pub fn active_at(&self, height: u64) -> bool {
        self.active_from_l2_height <= height && height <= self.active_until_l2_height
    }

    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotationReceipt {
    pub rotation_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub status: RotationStatus,
    pub activates_at_l2_height: u64,
    pub grace_until_l2_height: u64,
    pub rotation_authority_root: String,
    pub rotation_root: String,
}

impl RotationReceipt {
    pub fn active_for_signature(&self, height: u64, epoch: u64) -> bool {
        self.to_epoch == epoch
            && self.status.permits_signature()
            && self.activates_at_l2_height <= height
            && height <= self.grace_until_l2_height
    }

    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalAuthorityLink {
    pub authority_id: String,
    pub authority_epoch: u64,
    pub withdrawal_claim_root: String,
    pub wallet_recovery_root: String,
    pub release_instruction_root: String,
    pub authority_root: String,
}

impl WithdrawalAuthorityLink {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TranscriptBinding {
    pub transcript_id: String,
    pub exit_claim_root: String,
    pub private_note_root: String,
    pub monero_lock_root: String,
    pub reserve_proof_root: String,
    pub domain_root: String,
    pub transcript_root: String,
}

impl TranscriptBinding {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerQuorumReceipt {
    pub receipt_id: String,
    pub signer_id: String,
    pub signer_root: String,
    pub key_epoch: u64,
    pub signature_domain_root: String,
    pub transcript_root: String,
    pub signature_share_root: String,
    pub observed_l2_height: u64,
    pub weight_bps: u16,
    pub receipt_root: String,
}

impl SignerQuorumReceipt {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestationReceipt {
    pub receipt_id: String,
    pub watcher_id: String,
    pub watcher_root: String,
    pub key_epoch: u64,
    pub signature_domain_root: String,
    pub withdrawal_authority_root: String,
    pub transcript_root: String,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub weight_bps: u16,
    pub attestation_root: String,
}

impl WatcherAttestationReceipt {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThresholdWeights {
    pub signer_weight_bps: u16,
    pub watcher_weight_bps: u16,
    pub combined_weight_bps: u16,
    pub signer_count: u16,
    pub watcher_count: u16,
    pub signer_threshold_met: bool,
    pub watcher_threshold_met: bool,
    pub combined_threshold_met: bool,
    pub threshold_root: String,
}

impl ThresholdWeights {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureHold {
    pub hold_id: String,
    pub reason: HoldReason,
    pub source_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub blocks_signature: bool,
    pub hold_root: String,
}

impl SignatureHold {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CustodySignatureReceipt {
    pub receipt_id: String,
    pub status: ReceiptStatus,
    pub key_epoch: u64,
    pub signer_quorum_root: String,
    pub signature_domain_root: String,
    pub key_epoch_receipt_root: String,
    pub watcher_attestation_root: String,
    pub threshold_weight_root: String,
    pub rotation_status_root: String,
    pub withdrawal_authority_root: String,
    pub transcript_root: String,
    pub hold_root: String,
    pub issued_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub receipt_root: String,
}

impl CustodySignatureReceipt {
    pub fn public_record(&self) -> Value {
        json_record(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateRoots {
    pub config_root: String,
    pub signer_set_root: String,
    pub watcher_set_root: String,
    pub key_epoch_root: String,
    pub rotation_root: String,
    pub withdrawal_authority_root: String,
    pub transcript_root: String,
    pub signature_domain_root: String,
    pub signer_quorum_root: String,
    pub watcher_attestation_root: String,
    pub threshold_weight_root: String,
    pub hold_root: String,
    pub receipt_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub signers: BTreeMap<String, SignerWeight>,
    pub watchers: BTreeMap<String, WatcherWeight>,
    pub key_epochs: BTreeMap<u64, KeyEpochReceipt>,
    pub rotations: BTreeMap<String, RotationReceipt>,
    pub withdrawal_authorities: BTreeMap<String, WithdrawalAuthorityLink>,
    pub transcripts: BTreeMap<String, TranscriptBinding>,
    pub signature_domains: BTreeMap<String, SignatureDomainRoot>,
    pub signer_receipts: BTreeMap<String, SignerQuorumReceipt>,
    pub watcher_receipts: BTreeMap<String, WatcherAttestationReceipt>,
    pub threshold_weights: BTreeMap<String, ThresholdWeights>,
    pub holds: BTreeMap<String, SignatureHold>,
    pub custody_receipts: BTreeMap<String, CustodySignatureReceipt>,
    pub roots: StateRoots,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            signers: BTreeMap::new(),
            watchers: BTreeMap::new(),
            key_epochs: BTreeMap::new(),
            rotations: BTreeMap::new(),
            withdrawal_authorities: BTreeMap::new(),
            transcripts: BTreeMap::new(),
            signature_domains: BTreeMap::new(),
            signer_receipts: BTreeMap::new(),
            watcher_receipts: BTreeMap::new(),
            threshold_weights: BTreeMap::new(),
            holds: BTreeMap::new(),
            custody_receipts: BTreeMap::new(),
            roots: StateRoots::default(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone());

        let signers = vec![
            signer("custody-signer-a", SignerRole::CustodyCouncil, 2_600, 256),
            signer("custody-signer-b", SignerRole::CustodyCouncil, 2_400, 256),
            signer(
                "withdrawal-signer-c",
                SignerRole::WithdrawalCouncil,
                2_100,
                256,
            ),
            signer("reserve-signer-d", SignerRole::ReserveCouncil, 1_500, 256),
            signer(
                "emergency-signer-e",
                SignerRole::EmergencyCouncil,
                1_400,
                256,
            ),
        ];
        for signer in signers {
            state.signers.insert(signer.signer_id.clone(), signer);
        }

        let watchers = vec![
            watcher("watcher-monero-lock-a", WatcherKind::MoneroLock, 2_200),
            watcher("watcher-l2-burn-b", WatcherKind::L2Burn, 2_100),
            watcher("watcher-challenge-c", WatcherKind::ChallengeWindow, 1_800),
            watcher(
                "watcher-settlement-d",
                WatcherKind::SettlementReceipt,
                1_700,
            ),
            watcher("watcher-reserve-e", WatcherKind::ReserveProof, 1_300),
        ];
        for watcher in watchers {
            state.watchers.insert(watcher.watcher_id.clone(), watcher);
        }

        let withdrawal_authority = withdrawal_authority(&config);
        state.withdrawal_authorities.insert(
            withdrawal_authority.authority_id.clone(),
            withdrawal_authority.clone(),
        );

        let transcript = transcript_binding(&withdrawal_authority.authority_root);
        state
            .transcripts
            .insert(transcript.transcript_id.clone(), transcript.clone());

        let domain = signature_domain(&config, &withdrawal_authority, &transcript);
        state
            .signature_domains
            .insert(domain.domain_id.clone(), domain.clone());

        let signer_set_root = vector_root(
            "PQCSR-SIGNER-SET",
            &state.signers.values().cloned().collect::<Vec<_>>(),
        );
        let watcher_set_root = vector_root(
            "PQCSR-WATCHER-SET",
            &state.watchers.values().cloned().collect::<Vec<_>>(),
        );
        let previous_epoch_root = label_root("previous-key-epoch", "devnet-epoch-72");
        let key_epoch = key_epoch_receipt(
            &config,
            previous_epoch_root,
            signer_set_root,
            watcher_set_root,
            withdrawal_authority.authority_root.clone(),
        );
        state
            .key_epochs
            .insert(key_epoch.epoch_number, key_epoch.clone());

        let rotation = rotation_receipt(&config, &key_epoch);
        state
            .rotations
            .insert(rotation.rotation_id.clone(), rotation.clone());

        for signer_id in [
            "custody-signer-a",
            "custody-signer-b",
            "withdrawal-signer-c",
            "reserve-signer-d",
        ] {
            if let Some(signer_weight) = state.signers.get(signer_id) {
                let receipt = signer_receipt(&config, signer_weight, &key_epoch, &domain);
                state
                    .signer_receipts
                    .insert(receipt.receipt_id.clone(), receipt);
            }
        }

        for watcher_id in [
            "watcher-monero-lock-a",
            "watcher-l2-burn-b",
            "watcher-challenge-c",
            "watcher-settlement-d",
        ] {
            if let Some(watcher_weight) = state.watchers.get(watcher_id) {
                let receipt = watcher_attestation(
                    &config,
                    watcher_weight,
                    &key_epoch,
                    &domain,
                    &withdrawal_authority,
                );
                state
                    .watcher_receipts
                    .insert(receipt.receipt_id.clone(), receipt);
            }
        }

        let weights = state.threshold_weights_for(&domain.domain_root);
        state
            .threshold_weights
            .insert("devnet-threshold-weights".to_string(), weights);

        let holds = state.evaluate_holds(&key_epoch, &rotation, &withdrawal_authority, &domain);
        for hold in holds {
            state.holds.insert(hold.hold_id.clone(), hold);
        }

        let receipt = state.custody_signature_receipt(&key_epoch, &rotation, &withdrawal_authority);
        state
            .custody_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        state.recompute_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "custody_receipts": self.custody_receipts.values().map(CustodySignatureReceipt::public_record).collect::<Vec<_>>(),
            "holds": self.holds.values().map(SignatureHold::public_record).collect::<Vec<_>>(),
            "key_epochs": self.key_epochs.values().map(KeyEpochReceipt::public_record).collect::<Vec<_>>(),
            "protocol_version": self.config.protocol_version,
            "roots": self.roots,
            "signature_domains": self.signature_domains.values().map(SignatureDomainRoot::public_record).collect::<Vec<_>>(),
            "signer_receipts": self.signer_receipts.values().map(SignerQuorumReceipt::public_record).collect::<Vec<_>>(),
            "threshold_weights": self.threshold_weights.values().map(ThresholdWeights::public_record).collect::<Vec<_>>(),
            "transcripts": self.transcripts.values().map(TranscriptBinding::public_record).collect::<Vec<_>>(),
            "watcher_receipts": self.watcher_receipts.values().map(WatcherAttestationReceipt::public_record).collect::<Vec<_>>(),
            "withdrawal_authorities": self.withdrawal_authorities.values().map(WithdrawalAuthorityLink::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn verify(
        &self,
    ) -> MoneroL2PqBridgeExitCanonicalVerticalSlicePqCustodySignatureReceiptRuntimeResult<bool>
    {
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.custody_receipts.is_empty() {
            return Err("missing custody signature receipt".to_string());
        }
        Ok(self
            .custody_receipts
            .values()
            .all(|receipt| receipt.status == ReceiptStatus::Signed)
            && self.holds.is_empty())
    }

    fn threshold_weights_for(&self, domain_root: &str) -> ThresholdWeights {
        let signer_receipts = self
            .signer_receipts
            .values()
            .filter(|receipt| receipt.signature_domain_root == domain_root)
            .collect::<Vec<_>>();
        let watcher_receipts = self
            .watcher_receipts
            .values()
            .filter(|receipt| receipt.signature_domain_root == domain_root)
            .collect::<Vec<_>>();
        let signer_weight_bps = capped_bps(
            signer_receipts
                .iter()
                .map(|receipt| receipt.weight_bps)
                .sum(),
        );
        let watcher_weight_bps = capped_bps(
            watcher_receipts
                .iter()
                .map(|receipt| receipt.weight_bps)
                .sum(),
        );
        let combined_weight_bps =
            capped_bps(((signer_weight_bps as u32 + watcher_weight_bps as u32) / 2) as u16);
        let signer_count = signer_receipts.len() as u16;
        let watcher_count = watcher_receipts.len() as u16;
        let signer_threshold_met = signer_weight_bps >= self.config.min_signer_weight_bps
            && signer_count >= self.config.min_signer_count;
        let watcher_threshold_met = watcher_weight_bps >= self.config.min_watcher_weight_bps
            && watcher_count >= self.config.min_watcher_count;
        let combined_threshold_met = combined_weight_bps >= self.config.min_combined_weight_bps;
        let payload = json!({
            "combined_threshold_met": combined_threshold_met,
            "combined_weight_bps": combined_weight_bps,
            "signer_count": signer_count,
            "signer_threshold_met": signer_threshold_met,
            "signer_weight_bps": signer_weight_bps,
            "watcher_count": watcher_count,
            "watcher_threshold_met": watcher_threshold_met,
            "watcher_weight_bps": watcher_weight_bps,
        });
        let threshold_root = record_root("THRESHOLD-WEIGHTS", &payload);
        ThresholdWeights {
            signer_weight_bps,
            watcher_weight_bps,
            combined_weight_bps,
            signer_count,
            watcher_count,
            signer_threshold_met,
            watcher_threshold_met,
            combined_threshold_met,
            threshold_root,
        }
    }

    fn evaluate_holds(
        &self,
        key_epoch: &KeyEpochReceipt,
        rotation: &RotationReceipt,
        withdrawal_authority: &WithdrawalAuthorityLink,
        domain: &SignatureDomainRoot,
    ) -> Vec<SignatureHold> {
        let mut holds = Vec::new();
        let weights = self.threshold_weights_for(&domain.domain_root);
        if !weights.signer_threshold_met {
            holds.push(signature_hold(
                HoldReason::SignerWeightShortfall,
                weights.threshold_root.clone(),
                self.config.min_signer_weight_bps.to_string(),
                weights.signer_weight_bps.to_string(),
            ));
        }
        if !weights.watcher_threshold_met {
            holds.push(signature_hold(
                HoldReason::WatcherWeightShortfall,
                weights.threshold_root.clone(),
                self.config.min_watcher_weight_bps.to_string(),
                weights.watcher_weight_bps.to_string(),
            ));
        }
        if !weights.combined_threshold_met {
            holds.push(signature_hold(
                HoldReason::CombinedWeightShortfall,
                weights.threshold_root,
                self.config.min_combined_weight_bps.to_string(),
                weights.combined_weight_bps.to_string(),
            ));
        }
        if !key_epoch.active_at(self.config.l2_height) {
            holds.push(signature_hold(
                HoldReason::KeyEpochMismatch,
                key_epoch.receipt_root.clone(),
                "active".to_string(),
                "inactive".to_string(),
            ));
        }
        if !rotation.active_for_signature(self.config.l2_height, key_epoch.epoch_number) {
            holds.push(signature_hold(
                HoldReason::RotationNotActive,
                rotation.rotation_root.clone(),
                "active_or_grace".to_string(),
                rotation.status.as_str().to_string(),
            ));
        }
        if key_epoch.withdrawal_authority_root != withdrawal_authority.authority_root
            || domain.withdrawal_authority_root != withdrawal_authority.authority_root
        {
            holds.push(signature_hold(
                HoldReason::WithdrawalAuthorityMismatch,
                withdrawal_authority.authority_root.clone(),
                key_epoch.withdrawal_authority_root.clone(),
                domain.withdrawal_authority_root.clone(),
            ));
        }
        holds.extend(self.receipt_consistency_holds(key_epoch, withdrawal_authority, domain));
        holds
    }

    fn receipt_consistency_holds(
        &self,
        key_epoch: &KeyEpochReceipt,
        withdrawal_authority: &WithdrawalAuthorityLink,
        domain: &SignatureDomainRoot,
    ) -> Vec<SignatureHold> {
        let mut holds = Vec::new();
        let mut signer_ids = BTreeMap::<String, u16>::new();
        for receipt in self.signer_receipts.values() {
            let count = signer_ids.entry(receipt.signer_id.clone()).or_insert(0);
            *count += 1;
            let signer_matches = self
                .signers
                .get(&receipt.signer_id)
                .map(|signer| {
                    signer.signer_root == receipt.signer_root
                        && signer.active_at(receipt.observed_l2_height)
                        && signer.pq_security_bits >= self.config.min_pq_security_bits
                })
                .unwrap_or(false);
            if !signer_matches
                || receipt.key_epoch != key_epoch.epoch_number
                || receipt.signature_domain_root != domain.domain_root
                || receipt.transcript_root != domain.transcript_root
            {
                holds.push(signature_hold(
                    HoldReason::SignatureDomainMismatch,
                    receipt.receipt_root.clone(),
                    domain.domain_root.clone(),
                    receipt.signature_domain_root.clone(),
                ));
            }
        }
        for (signer_id, count) in signer_ids {
            if count > 1 {
                holds.push(signature_hold(
                    HoldReason::DuplicateSigner,
                    label_root("duplicate-signer", &signer_id),
                    "single".to_string(),
                    count.to_string(),
                ));
            }
        }
        let mut watcher_ids = BTreeMap::<String, u16>::new();
        for receipt in self.watcher_receipts.values() {
            let count = watcher_ids.entry(receipt.watcher_id.clone()).or_insert(0);
            *count += 1;
            let watcher_matches = self
                .watchers
                .get(&receipt.watcher_id)
                .map(|watcher| {
                    watcher.watcher_root == receipt.watcher_root
                        && watcher.active_at(receipt.observed_l2_height)
                        && watcher.pq_security_bits >= self.config.min_pq_security_bits
                })
                .unwrap_or(false);
            if !watcher_matches
                || receipt.key_epoch != key_epoch.epoch_number
                || receipt.signature_domain_root != domain.domain_root
                || receipt.withdrawal_authority_root != withdrawal_authority.authority_root
                || receipt.transcript_root != domain.transcript_root
            {
                holds.push(signature_hold(
                    HoldReason::MissingWatcherAttestation,
                    receipt.attestation_root.clone(),
                    domain.transcript_root.clone(),
                    receipt.transcript_root.clone(),
                ));
            }
        }
        for (watcher_id, count) in watcher_ids {
            if count > 1 {
                holds.push(signature_hold(
                    HoldReason::DuplicateWatcher,
                    label_root("duplicate-watcher", &watcher_id),
                    "single".to_string(),
                    count.to_string(),
                ));
            }
        }
        holds
    }

    fn custody_signature_receipt(
        &self,
        key_epoch: &KeyEpochReceipt,
        rotation: &RotationReceipt,
        withdrawal_authority: &WithdrawalAuthorityLink,
    ) -> CustodySignatureReceipt {
        let signer_quorum_root = vector_root(
            "PQCSR-SIGNER-QUORUM-RECEIPTS",
            &self.signer_receipts.values().cloned().collect::<Vec<_>>(),
        );
        let watcher_attestation_root = vector_root(
            "PQCSR-WATCHER-ATTESTATION-RECEIPTS",
            &self.watcher_receipts.values().cloned().collect::<Vec<_>>(),
        );
        let threshold_weight_root = vector_root(
            "PQCSR-THRESHOLD-WEIGHTS",
            &self.threshold_weights.values().cloned().collect::<Vec<_>>(),
        );
        let signature_domain_root = vector_root(
            "PQCSR-SIGNATURE-DOMAINS",
            &self.signature_domains.values().cloned().collect::<Vec<_>>(),
        );
        let transcript_root = vector_root(
            "PQCSR-TRANSCRIPT-BINDINGS",
            &self.transcripts.values().cloned().collect::<Vec<_>>(),
        );
        let hold_root = vector_root(
            "PQCSR-SIGNATURE-HOLDS",
            &self.holds.values().cloned().collect::<Vec<_>>(),
        );
        let status = if self.holds.is_empty() {
            ReceiptStatus::Signed
        } else {
            ReceiptStatus::Held
        };
        let expires_at_l2_height = self.config.l2_height + self.config.receipt_ttl_blocks;
        let payload = json!({
            "expires_at_l2_height": expires_at_l2_height,
            "hold_root": hold_root,
            "issued_at_l2_height": self.config.l2_height,
            "key_epoch": key_epoch.epoch_number,
            "key_epoch_receipt_root": key_epoch.receipt_root,
            "rotation_status_root": rotation.rotation_root,
            "signature_domain_root": signature_domain_root,
            "signer_quorum_root": signer_quorum_root,
            "status": status.as_str(),
            "threshold_weight_root": threshold_weight_root,
            "transcript_root": transcript_root,
            "watcher_attestation_root": watcher_attestation_root,
            "withdrawal_authority_root": withdrawal_authority.authority_root,
        });
        let receipt_root = record_root("CUSTODY-SIGNATURE-RECEIPT", &payload);
        CustodySignatureReceipt {
            receipt_id: id_root("custody-signature-receipt", &receipt_root),
            status,
            key_epoch: key_epoch.epoch_number,
            signer_quorum_root,
            signature_domain_root,
            key_epoch_receipt_root: key_epoch.receipt_root.clone(),
            watcher_attestation_root,
            threshold_weight_root,
            rotation_status_root: rotation.rotation_root.clone(),
            withdrawal_authority_root: withdrawal_authority.authority_root.clone(),
            transcript_root,
            hold_root,
            issued_at_l2_height: self.config.l2_height,
            expires_at_l2_height,
            receipt_root,
        }
    }

    fn recompute_roots(&mut self) {
        let config_root = self.config.root();
        let signer_set_root = vector_root(
            "PQCSR-STATE-SIGNERS",
            &self.signers.values().cloned().collect::<Vec<_>>(),
        );
        let watcher_set_root = vector_root(
            "PQCSR-STATE-WATCHERS",
            &self.watchers.values().cloned().collect::<Vec<_>>(),
        );
        let key_epoch_root = vector_root(
            "PQCSR-STATE-KEY-EPOCHS",
            &self.key_epochs.values().cloned().collect::<Vec<_>>(),
        );
        let rotation_root = vector_root(
            "PQCSR-STATE-ROTATIONS",
            &self.rotations.values().cloned().collect::<Vec<_>>(),
        );
        let withdrawal_authority_root = vector_root(
            "PQCSR-STATE-WITHDRAWAL-AUTHORITY",
            &self
                .withdrawal_authorities
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        );
        let transcript_root = vector_root(
            "PQCSR-STATE-TRANSCRIPTS",
            &self.transcripts.values().cloned().collect::<Vec<_>>(),
        );
        let signature_domain_root = vector_root(
            "PQCSR-STATE-SIGNATURE-DOMAINS",
            &self.signature_domains.values().cloned().collect::<Vec<_>>(),
        );
        let signer_quorum_root = vector_root(
            "PQCSR-STATE-SIGNER-RECEIPTS",
            &self.signer_receipts.values().cloned().collect::<Vec<_>>(),
        );
        let watcher_attestation_root = vector_root(
            "PQCSR-STATE-WATCHER-RECEIPTS",
            &self.watcher_receipts.values().cloned().collect::<Vec<_>>(),
        );
        let threshold_weight_root = vector_root(
            "PQCSR-STATE-THRESHOLD-WEIGHTS",
            &self.threshold_weights.values().cloned().collect::<Vec<_>>(),
        );
        let hold_root = vector_root(
            "PQCSR-STATE-HOLDS",
            &self.holds.values().cloned().collect::<Vec<_>>(),
        );
        let receipt_root = vector_root(
            "PQCSR-STATE-CUSTODY-RECEIPTS",
            &self.custody_receipts.values().cloned().collect::<Vec<_>>(),
        );
        let public_record_payload = json!({
            "config_root": config_root,
            "hold_root": hold_root,
            "key_epoch_root": key_epoch_root,
            "receipt_root": receipt_root,
            "rotation_root": rotation_root,
            "signature_domain_root": signature_domain_root,
            "signer_quorum_root": signer_quorum_root,
            "threshold_weight_root": threshold_weight_root,
            "transcript_root": transcript_root,
            "watcher_attestation_root": watcher_attestation_root,
            "withdrawal_authority_root": withdrawal_authority_root,
        });
        let public_record_root = record_root("PUBLIC-RECORD", &public_record_payload);
        let state_payload = json!({
            "config_root": config_root,
            "height": self.config.l2_height,
            "protocol_version": self.config.protocol_version,
            "public_record_root": public_record_root,
            "receipt_root": receipt_root,
        });
        let state_root = record_root("STATE", &state_payload);
        self.roots = StateRoots {
            config_root,
            signer_set_root,
            watcher_set_root,
            key_epoch_root,
            rotation_root,
            withdrawal_authority_root,
            transcript_root,
            signature_domain_root,
            signer_quorum_root,
            watcher_attestation_root,
            threshold_weight_root,
            hold_root,
            receipt_root,
            public_record_root,
            state_root,
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

fn signer(id: &str, role: SignerRole, weight_bps: u16, pq_security_bits: u16) -> SignerWeight {
    let payload = json!({
        "active_from_l2_height": DEFAULT_L2_HEIGHT - 10_000,
        "active_until_l2_height": DEFAULT_L2_HEIGHT + 10_000,
        "pq_security_bits": pq_security_bits,
        "role": role.as_str(),
        "signer_id": id,
        "weight_bps": weight_bps,
    });
    let signer_root = record_root("SIGNER-WEIGHT", &payload);
    SignerWeight {
        signer_id: id.to_string(),
        role,
        weight_bps,
        pq_security_bits,
        active_from_l2_height: DEFAULT_L2_HEIGHT - 10_000,
        active_until_l2_height: DEFAULT_L2_HEIGHT + 10_000,
        signer_root,
    }
}

fn watcher(id: &str, kind: WatcherKind, weight_bps: u16) -> WatcherWeight {
    let payload = json!({
        "active_from_l2_height": DEFAULT_L2_HEIGHT - 10_000,
        "active_until_l2_height": DEFAULT_L2_HEIGHT + 10_000,
        "kind": kind.as_str(),
        "pq_security_bits": DEFAULT_MIN_PQ_SECURITY_BITS,
        "watcher_id": id,
        "weight_bps": weight_bps,
    });
    let watcher_root = record_root("WATCHER-WEIGHT", &payload);
    WatcherWeight {
        watcher_id: id.to_string(),
        kind,
        weight_bps,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        active_from_l2_height: DEFAULT_L2_HEIGHT - 10_000,
        active_until_l2_height: DEFAULT_L2_HEIGHT + 10_000,
        watcher_root,
    }
}

fn withdrawal_authority(config: &Config) -> WithdrawalAuthorityLink {
    let withdrawal_claim_root = label_root("withdrawal-claim", "forced-exit-claim-devnet-0001");
    let wallet_recovery_root = label_root("wallet-recovery", "jamtis-recovery-devnet-0001");
    let release_instruction_root =
        label_root("release-instruction", "monero-release-plan-devnet-0001");
    let payload = json!({
        "authority_epoch": config.authority_epoch,
        "release_instruction_root": release_instruction_root,
        "wallet_recovery_root": wallet_recovery_root,
        "withdrawal_claim_root": withdrawal_claim_root,
    });
    let authority_root = record_root("WITHDRAWAL-AUTHORITY-LINK", &payload);
    WithdrawalAuthorityLink {
        authority_id: id_root("withdrawal-authority", &authority_root),
        authority_epoch: config.authority_epoch,
        withdrawal_claim_root,
        wallet_recovery_root,
        release_instruction_root,
        authority_root,
    }
}

fn transcript_binding(withdrawal_authority_root: &str) -> TranscriptBinding {
    let exit_claim_root = label_root("exit-claim", "forced-exit-claim-devnet-0001");
    let private_note_root = label_root("private-note", "note-commitment-devnet-9f31");
    let monero_lock_root = label_root("monero-lock", "monero-lock-output-devnet-7a12");
    let reserve_proof_root = label_root("reserve-proof", "reserve-proof-devnet-aa01");
    let payload = json!({
        "domain_root": withdrawal_authority_root,
        "exit_claim_root": exit_claim_root,
        "monero_lock_root": monero_lock_root,
        "private_note_root": private_note_root,
        "reserve_proof_root": reserve_proof_root,
    });
    let transcript_root = record_root("TRANSCRIPT-BINDING", &payload);
    TranscriptBinding {
        transcript_id: id_root("transcript", &transcript_root),
        exit_claim_root,
        private_note_root,
        monero_lock_root,
        reserve_proof_root,
        domain_root: withdrawal_authority_root.to_string(),
        transcript_root,
    }
}

fn signature_domain(
    config: &Config,
    authority: &WithdrawalAuthorityLink,
    transcript: &TranscriptBinding,
) -> SignatureDomainRoot {
    let challenge_window_root = label_root("challenge-window", "closed-devnet-884360");
    let payload = json!({
        "authority_epoch": config.authority_epoch,
        "challenge_window_root": challenge_window_root,
        "kind": SignatureDomainKind::CustodyAuthorization.as_str(),
        "scheme": PqSignatureScheme::HybridMlDsaSlhDsaShake.as_str(),
        "transcript_root": transcript.transcript_root,
        "withdrawal_authority_root": authority.authority_root,
    });
    let domain_root = record_root("SIGNATURE-DOMAIN", &payload);
    SignatureDomainRoot {
        domain_id: id_root("signature-domain", &domain_root),
        kind: SignatureDomainKind::CustodyAuthorization,
        scheme: PqSignatureScheme::HybridMlDsaSlhDsaShake,
        authority_epoch: config.authority_epoch,
        withdrawal_authority_root: authority.authority_root.clone(),
        transcript_root: transcript.transcript_root.clone(),
        challenge_window_root,
        domain_root,
    }
}

fn key_epoch_receipt(
    config: &Config,
    previous_epoch_root: String,
    signer_set_root: String,
    watcher_set_root: String,
    withdrawal_authority_root: String,
) -> KeyEpochReceipt {
    let starts_at_l2_height = config.l2_height - 240;
    let expires_at_l2_height = config.l2_height + 2_880;
    let payload = json!({
        "epoch_number": config.authority_epoch,
        "expires_at_l2_height": expires_at_l2_height,
        "previous_epoch_root": previous_epoch_root,
        "signer_set_root": signer_set_root,
        "starts_at_l2_height": starts_at_l2_height,
        "watcher_set_root": watcher_set_root,
        "withdrawal_authority_root": withdrawal_authority_root,
    });
    let receipt_root = record_root("KEY-EPOCH-RECEIPT", &payload);
    KeyEpochReceipt {
        epoch_id: id_root("key-epoch", &receipt_root),
        epoch_number: config.authority_epoch,
        previous_epoch_root,
        signer_set_root,
        watcher_set_root,
        withdrawal_authority_root,
        starts_at_l2_height,
        expires_at_l2_height,
        receipt_root,
    }
}

fn rotation_receipt(config: &Config, key_epoch: &KeyEpochReceipt) -> RotationReceipt {
    let activates_at_l2_height = key_epoch.starts_at_l2_height;
    let grace_until_l2_height = key_epoch.expires_at_l2_height + config.rotation_grace_blocks;
    let rotation_authority_root = label_root("rotation-authority", "pq-custody-rotation-board");
    let payload = json!({
        "activates_at_l2_height": activates_at_l2_height,
        "from_epoch": key_epoch.epoch_number - 1,
        "grace_until_l2_height": grace_until_l2_height,
        "rotation_authority_root": rotation_authority_root,
        "status": RotationStatus::Active.as_str(),
        "to_epoch": key_epoch.epoch_number,
    });
    let rotation_root = record_root("ROTATION-RECEIPT", &payload);
    RotationReceipt {
        rotation_id: id_root("rotation", &rotation_root),
        from_epoch: key_epoch.epoch_number - 1,
        to_epoch: key_epoch.epoch_number,
        status: RotationStatus::Active,
        activates_at_l2_height,
        grace_until_l2_height,
        rotation_authority_root,
        rotation_root,
    }
}

fn signer_receipt(
    config: &Config,
    signer: &SignerWeight,
    key_epoch: &KeyEpochReceipt,
    domain: &SignatureDomainRoot,
) -> SignerQuorumReceipt {
    let signature_share_root = domain_hash(
        "PQCSR-SIGNATURE-SHARE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&signer.signer_root),
            HashPart::Str(&domain.domain_root),
            HashPart::Str(&domain.transcript_root),
            HashPart::Int(key_epoch.epoch_number as i128),
        ],
        32,
    );
    let payload = json!({
        "key_epoch": key_epoch.epoch_number,
        "observed_l2_height": config.l2_height,
        "signature_domain_root": domain.domain_root,
        "signature_share_root": signature_share_root,
        "signer_id": signer.signer_id,
        "signer_root": signer.signer_root,
        "transcript_root": domain.transcript_root,
        "weight_bps": signer.weight_bps,
    });
    let receipt_root = record_root("SIGNER-QUORUM-RECEIPT", &payload);
    SignerQuorumReceipt {
        receipt_id: id_root("signer-quorum-receipt", &receipt_root),
        signer_id: signer.signer_id.clone(),
        signer_root: signer.signer_root.clone(),
        key_epoch: key_epoch.epoch_number,
        signature_domain_root: domain.domain_root.clone(),
        transcript_root: domain.transcript_root.clone(),
        signature_share_root,
        observed_l2_height: config.l2_height,
        weight_bps: signer.weight_bps,
        receipt_root,
    }
}

fn watcher_attestation(
    config: &Config,
    watcher: &WatcherWeight,
    key_epoch: &KeyEpochReceipt,
    domain: &SignatureDomainRoot,
    authority: &WithdrawalAuthorityLink,
) -> WatcherAttestationReceipt {
    let payload = json!({
        "key_epoch": key_epoch.epoch_number,
        "observed_l2_height": config.l2_height,
        "observed_monero_height": config.monero_height,
        "signature_domain_root": domain.domain_root,
        "transcript_root": domain.transcript_root,
        "watcher_id": watcher.watcher_id,
        "watcher_root": watcher.watcher_root,
        "weight_bps": watcher.weight_bps,
        "withdrawal_authority_root": authority.authority_root,
    });
    let attestation_root = record_root("WATCHER-ATTESTATION-RECEIPT", &payload);
    WatcherAttestationReceipt {
        receipt_id: id_root("watcher-attestation-receipt", &attestation_root),
        watcher_id: watcher.watcher_id.clone(),
        watcher_root: watcher.watcher_root.clone(),
        key_epoch: key_epoch.epoch_number,
        signature_domain_root: domain.domain_root.clone(),
        withdrawal_authority_root: authority.authority_root.clone(),
        transcript_root: domain.transcript_root.clone(),
        observed_monero_height: config.monero_height,
        observed_l2_height: config.l2_height,
        weight_bps: watcher.weight_bps,
        attestation_root,
    }
}

fn signature_hold(
    reason: HoldReason,
    source_root: String,
    expected_root: String,
    observed_root: String,
) -> SignatureHold {
    let payload = json!({
        "blocks_signature": true,
        "expected_root": expected_root,
        "observed_root": observed_root,
        "reason": reason.as_str(),
        "source_root": source_root,
    });
    let hold_root = record_root("SIGNATURE-HOLD", &payload);
    SignatureHold {
        hold_id: id_root("signature-hold", &hold_root),
        reason,
        source_root,
        expected_root,
        observed_root,
        blocks_signature: true,
        hold_root,
    }
}

fn capped_bps(value: u16) -> u16 {
    value.min(MAX_BPS)
}

fn json_record<T: Serialize>(record: &T) -> Value {
    match serde_json::to_value(record) {
        Ok(value) => value,
        Err(error) => json!({
            "serialization_error": error.to_string(),
        }),
    }
}

fn vector_root<T: Serialize>(label: &str, records: &[T]) -> String {
    merkle_root(
        label,
        &records.iter().map(json_record).collect::<Vec<Value>>(),
    )
}

fn label_root(label: &str, value: &str) -> String {
    domain_hash(
        "PQ-CUSTODY-SIGNATURE-RECEIPT-LABEL",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn id_root(label: &str, root: &str) -> String {
    domain_hash(
        "PQ-CUSTODY-SIGNATURE-RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(root),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "PQ-CUSTODY-SIGNATURE-RECEIPT-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
