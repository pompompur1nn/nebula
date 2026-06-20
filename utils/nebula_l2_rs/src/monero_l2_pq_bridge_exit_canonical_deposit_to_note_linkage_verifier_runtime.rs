use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalDepositToNoteLinkageVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_DEPOSIT_TO_NOTE_LINKAGE_VERIFIER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-deposit-to-note-linkage-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_DEPOSIT_TO_NOTE_LINKAGE_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LINKAGE_SUITE: &str = "canonical-finalized-monero-deposit-to-private-l2-note-v1";
pub const FINALITY_SUITE: &str = "monero-finality-depth-with-reorg-guard-v1";
pub const RECEIPT_SUITE: &str = "encrypted-receipt-roots-only-v1";
pub const NULLIFIER_SUITE: &str = "deposit-nullifier-preimage-domain-separation-v1";
pub const SCAN_HINT_PRIVACY_SUITE: &str = "wallet-scan-hints-rooted-redacted-metadata-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_REORG_GUARD_BLOCKS: u64 = 6;
pub const DEFAULT_MIN_WITNESS_WEIGHT: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_FORCE_EXIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_510_560;
pub const DEFAULT_L2_HEIGHT: u64 = 4_220_320;
pub const DEFAULT_MAX_LINKAGES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Accepted,
    Rejected,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    None,
    DepositNotFinal,
    ReorgGuardGap,
    LockEvidenceRootMismatch,
    NoteCommitmentRootMismatch,
    EncryptedReceiptRootMismatch,
    NullifierPreimageCollision,
    WalletScanHintLeak,
    ForceExitBindingMissing,
    WitnessWeightInsufficient,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DepositNotFinal => "deposit_not_final",
            Self::ReorgGuardGap => "reorg_guard_gap",
            Self::LockEvidenceRootMismatch => "lock_evidence_root_mismatch",
            Self::NoteCommitmentRootMismatch => "note_commitment_root_mismatch",
            Self::EncryptedReceiptRootMismatch => "encrypted_receipt_root_mismatch",
            Self::NullifierPreimageCollision => "nullifier_preimage_collision",
            Self::WalletScanHintLeak => "wallet_scan_hint_leak",
            Self::ForceExitBindingMissing => "force_exit_binding_missing",
            Self::WitnessWeightInsufficient => "witness_weight_insufficient",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub linkage_suite: String,
    pub finality_suite: String,
    pub receipt_suite: String,
    pub nullifier_suite: String,
    pub scan_hint_privacy_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub min_confirmations: u64,
    pub reorg_guard_blocks: u64,
    pub min_witness_weight: u64,
    pub min_privacy_set_size: u64,
    pub force_exit_window_blocks: u64,
    pub base_monero_height: u64,
    pub l2_height: u64,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_linkages: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            linkage_suite: LINKAGE_SUITE.to_string(),
            finality_suite: FINALITY_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            nullifier_suite: NULLIFIER_SUITE.to_string(),
            scan_hint_privacy_suite: SCAN_HINT_PRIVACY_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_guard_blocks: DEFAULT_REORG_GUARD_BLOCKS,
            min_witness_weight: DEFAULT_MIN_WITNESS_WEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            force_exit_window_blocks: DEFAULT_FORCE_EXIT_WINDOW_BLOCKS,
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_height: DEFAULT_L2_HEIGHT,
            fail_closed: true,
            production_release_allowed: false,
            max_linkages: DEFAULT_MAX_LINKAGES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "linkage_suite": self.linkage_suite,
            "finality_suite": self.finality_suite,
            "receipt_suite": self.receipt_suite,
            "nullifier_suite": self.nullifier_suite,
            "scan_hint_privacy_suite": self.scan_hint_privacy_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "min_confirmations": self.min_confirmations,
            "reorg_guard_blocks": self.reorg_guard_blocks,
            "min_witness_weight": self.min_witness_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "force_exit_window_blocks": self.force_exit_window_blocks,
            "base_monero_height": self.base_monero_height,
            "l2_height": self.l2_height,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "max_linkages": self.max_linkages,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositFinality {
    pub lock_txid: String,
    pub output_index: u64,
    pub canonical_header_hash: String,
    pub competing_header_hash: String,
    pub observed_height: u64,
    pub observed_depth: u64,
    pub required_depth: u64,
    pub reorg_guard_blocks: u64,
    pub witness_weight: u64,
    pub witness_set_root: String,
}

impl DepositFinality {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_txid": self.lock_txid,
            "output_index": self.output_index,
            "canonical_header_hash": self.canonical_header_hash,
            "competing_header_hash": self.competing_header_hash,
            "observed_height": self.observed_height,
            "observed_depth": self.observed_depth,
            "required_depth": self.required_depth,
            "reorg_guard_blocks": self.reorg_guard_blocks,
            "witness_weight": self.witness_weight,
            "witness_set_root": self.witness_set_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("deposit_finality", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LinkageRoots {
    pub lock_evidence_root: String,
    pub expected_lock_evidence_root: String,
    pub note_commitment_root: String,
    pub expected_note_commitment_root: String,
    pub encrypted_receipt_root: String,
    pub expected_encrypted_receipt_root: String,
    pub nullifier_preimage_root: String,
    pub wallet_scan_hint_root: String,
    pub force_exit_claim_root: String,
    pub rejection_root: String,
    pub linkage_root: String,
}

impl LinkageRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_evidence_root": self.lock_evidence_root,
            "expected_lock_evidence_root": self.expected_lock_evidence_root,
            "note_commitment_root": self.note_commitment_root,
            "expected_note_commitment_root": self.expected_note_commitment_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "expected_encrypted_receipt_root": self.expected_encrypted_receipt_root,
            "nullifier_preimage_root": self.nullifier_preimage_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "force_exit_claim_root": self.force_exit_claim_root,
            "rejection_root": self.rejection_root,
            "linkage_root": self.linkage_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositToNoteLinkage {
    pub linkage_id: String,
    pub status: VerificationStatus,
    pub rejection_reason: RejectionReason,
    pub finality: DepositFinality,
    pub deposit_value_commitment: String,
    pub private_note_commitment: String,
    pub note_asset_id: String,
    pub note_owner_commitment_root: String,
    pub encrypted_receipt_ciphertext_root: String,
    pub encrypted_receipt_recipient_root: String,
    pub nullifier_domain: String,
    pub nullifier_preimage_commitment: String,
    pub wallet_scan_hint_policy: String,
    pub wallet_scan_hint_disclosure_root: String,
    pub privacy_set_size: u64,
    pub privately_spendable: bool,
    pub force_exitable: bool,
    pub roots: LinkageRoots,
}

impl DepositToNoteLinkage {
    pub fn public_record(&self) -> Value {
        json!({
            "linkage_id": self.linkage_id,
            "status": self.status.as_str(),
            "rejection_reason": self.rejection_reason.as_str(),
            "finality": self.finality.public_record(),
            "deposit_value_commitment": self.deposit_value_commitment,
            "private_note_commitment": self.private_note_commitment,
            "note_asset_id": self.note_asset_id,
            "note_owner_commitment_root": self.note_owner_commitment_root,
            "encrypted_receipt_ciphertext_root": self.encrypted_receipt_ciphertext_root,
            "encrypted_receipt_recipient_root": self.encrypted_receipt_recipient_root,
            "nullifier_domain": self.nullifier_domain,
            "nullifier_preimage_commitment": self.nullifier_preimage_commitment,
            "wallet_scan_hint_policy": self.wallet_scan_hint_policy,
            "wallet_scan_hint_disclosure_root": self.wallet_scan_hint_disclosure_root,
            "privacy_set_size": self.privacy_set_size,
            "privately_spendable": self.privately_spendable,
            "force_exitable": self.force_exitable,
            "roots": self.roots.public_record(),
        })
    }

    pub fn root(&self) -> String {
        linkage_root(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub accepted: u64,
    pub rejected: u64,
    pub privately_spendable: u64,
    pub force_exitable: u64,
    pub fail_closed_rejections: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "accepted": self.accepted,
            "rejected": self.rejected,
            "privately_spendable": self.privately_spendable,
            "force_exitable": self.force_exitable,
            "fail_closed_rejections": self.fail_closed_rejections,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub linkage_set_root: String,
    pub accepted_root: String,
    pub rejected_root: String,
    pub counters_root: String,
    pub devnet_data_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "linkage_set_root": self.linkage_set_root,
            "accepted_root": self.accepted_root,
            "rejected_root": self.rejected_root,
            "counters_root": self.counters_root,
            "devnet_data_root": self.devnet_data_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub linkages: Vec<DepositToNoteLinkage>,
    pub accepted_linkage_ids: Vec<String>,
    pub rejected_linkage_ids: Vec<String>,
    pub counters: Counters,
    pub devnet_data: BTreeMap<String, Value>,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, linkages: Vec<DepositToNoteLinkage>) -> Result<Self> {
        ensure(
            linkages.len() <= config.max_linkages,
            "linkage capacity exceeded",
        )?;
        let mut seen_notes = BTreeMap::<String, String>::new();
        let mut accepted_linkage_ids = Vec::new();
        let mut rejected_linkage_ids = Vec::new();
        let mut counters = Counters::default();

        for linkage in &linkages {
            ensure_linkage(&config, linkage)?;
            if let Some(existing) = seen_notes.insert(
                linkage.private_note_commitment.clone(),
                linkage.linkage_id.clone(),
            ) {
                return Err(format!(
                    "private note commitment collision between {} and {}",
                    existing, linkage.linkage_id
                ));
            }
            match linkage.status {
                VerificationStatus::Accepted => {
                    counters.accepted += 1;
                    accepted_linkage_ids.push(linkage.linkage_id.clone());
                }
                VerificationStatus::Rejected => {
                    counters.rejected += 1;
                    counters.fail_closed_rejections += 1;
                    rejected_linkage_ids.push(linkage.linkage_id.clone());
                }
            }
            if linkage.privately_spendable {
                counters.privately_spendable += 1;
            }
            if linkage.force_exitable {
                counters.force_exitable += 1;
            }
        }

        let devnet_data = devnet_data(&linkages);
        let roots = roots_for(
            &config,
            &linkages,
            &accepted_linkage_ids,
            &rejected_linkage_ids,
            &counters,
            &devnet_data,
        );
        Ok(Self {
            config,
            linkages,
            accepted_linkage_ids,
            rejected_linkage_ids,
            counters,
            devnet_data,
            roots,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let linkages = devnet_linkages(&config);
        match Self::new(config, linkages) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "linkages": self.linkages.iter().map(DepositToNoteLinkage::public_record).collect::<Vec<_>>(),
            "accepted_linkage_ids": self.accepted_linkage_ids,
            "rejected_linkage_ids": self.rejected_linkage_ids,
            "counters": self.counters.public_record(),
            "devnet_data": self.devnet_data,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
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

fn ensure_linkage(config: &Config, linkage: &DepositToNoteLinkage) -> Result<()> {
    let reason = evaluate_rejection(config, linkage);
    let expected_status = if reason == RejectionReason::None {
        VerificationStatus::Accepted
    } else {
        VerificationStatus::Rejected
    };
    ensure(
        linkage.status == expected_status,
        "linkage status does not match fail-closed evaluation",
    )?;
    ensure(
        linkage.rejection_reason == reason,
        "linkage rejection reason does not match fail-closed evaluation",
    )?;
    ensure(
        linkage.roots.linkage_root == linkage.root(),
        "linkage root mismatch",
    )?;
    Ok(())
}

fn evaluate_rejection(config: &Config, linkage: &DepositToNoteLinkage) -> RejectionReason {
    let finality_floor = linkage.finality.required_depth + linkage.finality.reorg_guard_blocks;
    if linkage.finality.observed_depth < linkage.finality.required_depth {
        return RejectionReason::DepositNotFinal;
    }
    if linkage.finality.observed_depth < finality_floor
        || linkage.finality.competing_header_hash != empty_root("no_competing_header")
    {
        return RejectionReason::ReorgGuardGap;
    }
    if linkage.finality.witness_weight < config.min_witness_weight {
        return RejectionReason::WitnessWeightInsufficient;
    }
    if linkage.roots.lock_evidence_root != linkage.roots.expected_lock_evidence_root {
        return RejectionReason::LockEvidenceRootMismatch;
    }
    if linkage.roots.note_commitment_root != linkage.roots.expected_note_commitment_root {
        return RejectionReason::NoteCommitmentRootMismatch;
    }
    if linkage.roots.encrypted_receipt_root != linkage.roots.expected_encrypted_receipt_root {
        return RejectionReason::EncryptedReceiptRootMismatch;
    }
    if linkage.nullifier_domain != NULLIFIER_SUITE
        || linkage.roots.nullifier_preimage_root == linkage.roots.lock_evidence_root
        || linkage.roots.nullifier_preimage_root == linkage.roots.note_commitment_root
    {
        return RejectionReason::NullifierPreimageCollision;
    }
    if linkage.wallet_scan_hint_policy != "redacted_root_only"
        || linkage.privacy_set_size < config.min_privacy_set_size
    {
        return RejectionReason::WalletScanHintLeak;
    }
    if !linkage.privately_spendable || !linkage.force_exitable {
        return RejectionReason::ForceExitBindingMissing;
    }
    RejectionReason::None
}

fn devnet_linkages(config: &Config) -> Vec<DepositToNoteLinkage> {
    vec![
        build_linkage(config, 0, RejectionReason::None),
        build_linkage(config, 1, RejectionReason::ReorgGuardGap),
        build_linkage(config, 2, RejectionReason::WalletScanHintLeak),
    ]
}

fn build_linkage(
    config: &Config,
    index: u64,
    forced_reason: RejectionReason,
) -> DepositToNoteLinkage {
    let seed = format!("deposit-to-note-devnet-{index}");
    let lock_txid = fixture_root("lock_txid", &seed);
    let output_index = index;
    let observed_depth = match forced_reason {
        RejectionReason::ReorgGuardGap => config.min_confirmations + 1,
        RejectionReason::DepositNotFinal => config.min_confirmations.saturating_sub(2),
        _ => config.min_confirmations + config.reorg_guard_blocks + 2,
    };
    let finality = DepositFinality {
        lock_txid: lock_txid.clone(),
        output_index,
        canonical_header_hash: fixture_root("canonical_header", &seed),
        competing_header_hash: empty_root("no_competing_header"),
        observed_height: config.base_monero_height + index * 9,
        observed_depth,
        required_depth: config.min_confirmations,
        reorg_guard_blocks: config.reorg_guard_blocks,
        witness_weight: config.min_witness_weight + 1,
        witness_set_root: fixture_root("witness_set", &seed),
    };
    let deposit_value_commitment = fixture_root("deposit_value_commitment", &seed);
    let private_note_commitment = fixture_root("private_note_commitment", &seed);
    let note_asset_id = fixture_root("note_asset_id", "canonical-xmr-asset");
    let note_owner_commitment_root = fixture_root("note_owner_commitment", &seed);
    let encrypted_receipt_ciphertext_root = fixture_root("encrypted_receipt_ciphertext", &seed);
    let encrypted_receipt_recipient_root = fixture_root("encrypted_receipt_recipient", &seed);
    let nullifier_preimage_commitment = fixture_root("nullifier_preimage", &seed);
    let wallet_scan_hint_policy = match forced_reason {
        RejectionReason::WalletScanHintLeak => "raw_wallet_scan_hint",
        _ => "redacted_root_only",
    }
    .to_string();
    let wallet_scan_hint_disclosure_root = scan_hint_root(&seed, &wallet_scan_hint_policy);
    let privacy_set_size = match forced_reason {
        RejectionReason::WalletScanHintLeak => config.min_privacy_set_size.saturating_sub(1),
        _ => config.min_privacy_set_size * 2,
    };
    let privately_spendable = forced_reason != RejectionReason::ForceExitBindingMissing;
    let force_exitable = forced_reason != RejectionReason::ForceExitBindingMissing;
    let mut roots = roots_for_linkage(
        &finality,
        &deposit_value_commitment,
        &private_note_commitment,
        &note_asset_id,
        &note_owner_commitment_root,
        &encrypted_receipt_ciphertext_root,
        &encrypted_receipt_recipient_root,
        &nullifier_preimage_commitment,
        &wallet_scan_hint_disclosure_root,
    );
    if forced_reason == RejectionReason::LockEvidenceRootMismatch {
        roots.lock_evidence_root = fixture_root("wrong_lock_evidence", &seed);
    }
    if forced_reason == RejectionReason::NoteCommitmentRootMismatch {
        roots.note_commitment_root = fixture_root("wrong_note_commitment", &seed);
    }
    if forced_reason == RejectionReason::EncryptedReceiptRootMismatch {
        roots.encrypted_receipt_root = fixture_root("wrong_receipt", &seed);
    }
    let status = if forced_reason == RejectionReason::None {
        VerificationStatus::Accepted
    } else {
        VerificationStatus::Rejected
    };
    roots.rejection_root = rejection_root(status, forced_reason, &roots);
    let linkage_id = stable_id("deposit_to_note_linkage", &roots.rejection_root);
    let mut linkage = DepositToNoteLinkage {
        linkage_id,
        status,
        rejection_reason: forced_reason,
        finality,
        deposit_value_commitment,
        private_note_commitment,
        note_asset_id,
        note_owner_commitment_root,
        encrypted_receipt_ciphertext_root,
        encrypted_receipt_recipient_root,
        nullifier_domain: NULLIFIER_SUITE.to_string(),
        nullifier_preimage_commitment,
        wallet_scan_hint_policy,
        wallet_scan_hint_disclosure_root,
        privacy_set_size,
        privately_spendable,
        force_exitable,
        roots,
    };
    linkage.roots.linkage_root = linkage.root();
    linkage
}

fn roots_for_linkage(
    finality: &DepositFinality,
    deposit_value_commitment: &str,
    private_note_commitment: &str,
    note_asset_id: &str,
    note_owner_commitment_root: &str,
    encrypted_receipt_ciphertext_root: &str,
    encrypted_receipt_recipient_root: &str,
    nullifier_preimage_commitment: &str,
    wallet_scan_hint_disclosure_root: &str,
) -> LinkageRoots {
    let lock_evidence_root = lock_evidence_root(finality, deposit_value_commitment);
    let note_commitment_root = note_commitment_root(
        &lock_evidence_root,
        private_note_commitment,
        note_asset_id,
        note_owner_commitment_root,
    );
    let encrypted_receipt_root = encrypted_receipt_root(
        &lock_evidence_root,
        &note_commitment_root,
        encrypted_receipt_ciphertext_root,
        encrypted_receipt_recipient_root,
    );
    let nullifier_preimage_root = nullifier_preimage_root(
        &lock_evidence_root,
        &note_commitment_root,
        nullifier_preimage_commitment,
    );
    LinkageRoots {
        lock_evidence_root: lock_evidence_root.clone(),
        expected_lock_evidence_root: lock_evidence_root,
        note_commitment_root: note_commitment_root.clone(),
        expected_note_commitment_root: note_commitment_root,
        encrypted_receipt_root: encrypted_receipt_root.clone(),
        expected_encrypted_receipt_root: encrypted_receipt_root,
        nullifier_preimage_root,
        wallet_scan_hint_root: wallet_scan_hint_disclosure_root.to_string(),
        force_exit_claim_root: force_exit_claim_root(private_note_commitment),
        rejection_root: String::new(),
        linkage_root: String::new(),
    }
}

fn roots_for(
    config: &Config,
    linkages: &[DepositToNoteLinkage],
    accepted_ids: &[String],
    rejected_ids: &[String],
    counters: &Counters,
    devnet_data: &BTreeMap<String, Value>,
) -> Roots {
    let config_root = record_root("config", &config.public_record());
    let linkage_set_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-LINKAGE-SET",
        &linkages
            .iter()
            .map(DepositToNoteLinkage::public_record)
            .collect::<Vec<_>>(),
    );
    let accepted_root = string_vec_root("accepted_linkages", accepted_ids);
    let rejected_root = string_vec_root("rejected_linkages", rejected_ids);
    let counters_root = record_root("counters", &counters.public_record());
    let devnet_data_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-LINKAGE-DEVNET-DATA",
        &devnet_data.values().cloned().collect::<Vec<_>>(),
    );
    let public_record_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-LINKAGE-PUBLIC-RECORD",
        &[
            json!({"config_root": config_root}),
            json!({"linkage_set_root": linkage_set_root}),
            json!({"accepted_root": accepted_root}),
            json!({"rejected_root": rejected_root}),
            json!({"counters_root": counters_root}),
            json!({"devnet_data_root": devnet_data_root}),
        ],
    );
    let state_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-LINKAGE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config_root),
            HashPart::Str(&linkage_set_root),
            HashPart::Str(&accepted_root),
            HashPart::Str(&rejected_root),
            HashPart::Str(&counters_root),
            HashPart::Str(&devnet_data_root),
            HashPart::Str(&public_record_root),
        ],
        32,
    );
    Roots {
        config_root,
        linkage_set_root,
        accepted_root,
        rejected_root,
        counters_root,
        devnet_data_root,
        public_record_root,
        state_root,
    }
}

fn linkage_root(linkage: &DepositToNoteLinkage) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-LINKAGE",
        &[
            HashPart::Str(&linkage.linkage_id),
            HashPart::Str(linkage.status.as_str()),
            HashPart::Str(linkage.rejection_reason.as_str()),
            HashPart::Str(&linkage.finality.root()),
            HashPart::Str(&linkage.deposit_value_commitment),
            HashPart::Str(&linkage.private_note_commitment),
            HashPart::Str(&linkage.note_asset_id),
            HashPart::Str(&linkage.note_owner_commitment_root),
            HashPart::Str(&linkage.encrypted_receipt_ciphertext_root),
            HashPart::Str(&linkage.encrypted_receipt_recipient_root),
            HashPart::Str(&linkage.nullifier_domain),
            HashPart::Str(&linkage.nullifier_preimage_commitment),
            HashPart::Str(&linkage.wallet_scan_hint_policy),
            HashPart::Str(&linkage.wallet_scan_hint_disclosure_root),
            HashPart::U64(linkage.privacy_set_size),
            HashPart::Str(if linkage.privately_spendable {
                "yes"
            } else {
                "no"
            }),
            HashPart::Str(if linkage.force_exitable { "yes" } else { "no" }),
            HashPart::Str(&linkage.roots.lock_evidence_root),
            HashPart::Str(&linkage.roots.expected_lock_evidence_root),
            HashPart::Str(&linkage.roots.note_commitment_root),
            HashPart::Str(&linkage.roots.expected_note_commitment_root),
            HashPart::Str(&linkage.roots.encrypted_receipt_root),
            HashPart::Str(&linkage.roots.expected_encrypted_receipt_root),
            HashPart::Str(&linkage.roots.nullifier_preimage_root),
            HashPart::Str(&linkage.roots.wallet_scan_hint_root),
            HashPart::Str(&linkage.roots.force_exit_claim_root),
            HashPart::Str(&linkage.roots.rejection_root),
        ],
        32,
    )
}

fn lock_evidence_root(finality: &DepositFinality, deposit_value_commitment: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-LOCK-EVIDENCE",
        &[
            HashPart::Str(&finality.root()),
            HashPart::Str(deposit_value_commitment),
            HashPart::Str(FINALITY_SUITE),
        ],
        32,
    )
}

fn note_commitment_root(
    lock_evidence_root: &str,
    private_note_commitment: &str,
    note_asset_id: &str,
    note_owner_commitment_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-COMMITMENT",
        &[
            HashPart::Str(lock_evidence_root),
            HashPart::Str(private_note_commitment),
            HashPart::Str(note_asset_id),
            HashPart::Str(note_owner_commitment_root),
        ],
        32,
    )
}

fn encrypted_receipt_root(
    lock_evidence_root: &str,
    note_commitment_root: &str,
    ciphertext_root: &str,
    recipient_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-ENCRYPTED-RECEIPT",
        &[
            HashPart::Str(RECEIPT_SUITE),
            HashPart::Str(lock_evidence_root),
            HashPart::Str(note_commitment_root),
            HashPart::Str(ciphertext_root),
            HashPart::Str(recipient_root),
        ],
        32,
    )
}

fn nullifier_preimage_root(
    lock_evidence_root: &str,
    note_commitment_root: &str,
    nullifier_preimage_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-NULLIFIER-PREIMAGE",
        &[
            HashPart::Str(NULLIFIER_SUITE),
            HashPart::Str(lock_evidence_root),
            HashPart::Str(note_commitment_root),
            HashPart::Str(nullifier_preimage_commitment),
        ],
        32,
    )
}

fn force_exit_claim_root(private_note_commitment: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-FORCE-EXIT-CLAIM",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(private_note_commitment),
            HashPart::Str("later_force_exit_enabled"),
        ],
        32,
    )
}

fn rejection_root(
    status: VerificationStatus,
    reason: RejectionReason,
    roots: &LinkageRoots,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-FAIL-CLOSED-REJECTION",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(reason.as_str()),
            HashPart::Str(&roots.lock_evidence_root),
            HashPart::Str(&roots.note_commitment_root),
            HashPart::Str(&roots.encrypted_receipt_root),
            HashPart::Str(&roots.nullifier_preimage_root),
            HashPart::Str(&roots.wallet_scan_hint_root),
            HashPart::Str(&roots.force_exit_claim_root),
        ],
        32,
    )
}

fn scan_hint_root(seed: &str, policy: &str) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-WALLET-SCAN-HINTS",
        &[
            json!({"field": "subaddress", "policy": policy}),
            json!({"field": "view_tag", "policy": policy}),
            json!({"field": "wallet_path", "policy": policy}),
            json!({"seed_root": fixture_root("scan_hint_seed", seed)}),
        ],
    )
}

fn devnet_data(linkages: &[DepositToNoteLinkage]) -> BTreeMap<String, Value> {
    let mut data = BTreeMap::new();
    data.insert(
        "canonical_question".to_string(),
        json!({
            "question": "is_this_deposited_value_privately_spendable_and_later_force_exitable",
            "accepted_answer": linkages.iter().any(|item| item.status == VerificationStatus::Accepted && item.privately_spendable && item.force_exitable),
            "public_inputs": [
                "lock_evidence_root",
                "note_commitment_root",
                "encrypted_receipt_root",
                "nullifier_preimage_root",
                "wallet_scan_hint_root",
                "force_exit_claim_root"
            ]
        }),
    );
    data.insert(
        "privacy_policy".to_string(),
        json!({
            "wallet_metadata_exposure": "roots_only",
            "scan_hint_policy": "redacted_root_only",
            "nullifier_preimage_separation": NULLIFIER_SUITE,
            "encrypted_receipts": RECEIPT_SUITE
        }),
    );
    data.insert(
        "fail_closed_reasons".to_string(),
        json!({
            "rejections": RejectionReason::all_public_strings(),
            "policy": "any ambiguous finality, root mismatch, scan hint leak, or force-exit gap rejects"
        }),
    );
    data
}

impl RejectionReason {
    fn all_public_strings() -> Vec<&'static str> {
        [
            Self::DepositNotFinal,
            Self::ReorgGuardGap,
            Self::LockEvidenceRootMismatch,
            Self::NoteCommitmentRootMismatch,
            Self::EncryptedReceiptRootMismatch,
            Self::NullifierPreimageCollision,
            Self::WalletScanHintLeak,
            Self::ForceExitBindingMissing,
            Self::WitnessWeightInsufficient,
        ]
        .iter()
        .map(|reason| reason.as_str())
        .collect()
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn string_vec_root(kind: &str, values: &[String]) -> String {
    merkle_root(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-{kind}"),
        &values
            .iter()
            .map(|value| json!({ "id": value }))
            .collect::<Vec<_>>(),
    )
}

fn fixture_root(kind: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-DEVNET-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn empty_root(kind: &str) -> String {
    merkle_root(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-EMPTY-{kind}"),
        &[],
    )
}

fn stable_id(kind: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-TO-NOTE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        16,
    )
}

fn fallback_state(reason: String) -> State {
    let config = Config::devnet();
    let mut devnet_data = BTreeMap::new();
    devnet_data.insert(
        "construction_error".to_string(),
        json!({"reason_root": fixture_root("construction_error", &reason)}),
    );
    let counters = Counters::default();
    let roots = roots_for(&config, &[], &[], &[], &counters, &devnet_data);
    State {
        config,
        linkages: Vec::new(),
        accepted_linkage_ids: Vec::new(),
        rejected_linkage_ids: Vec::new(),
        counters,
        devnet_data,
        roots,
    }
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
