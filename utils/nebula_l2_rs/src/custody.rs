use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type CustodyResult<T> = Result<T, String>;

pub const CUSTODY_PROTOCOL_VERSION: &str = "nebula-custody-v1";
pub const CUSTODY_DEFAULT_SWEEP_DELAY_BLOCKS: u64 = 2;
pub const CUSTODY_DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 4;
pub const CUSTODY_DEFAULT_FEE_BUMP_INTERVAL_BLOCKS: u64 = 3;
pub const CUSTODY_DEFAULT_MAX_FEE_BUMP_ATTEMPTS: u64 = 5;
pub const CUSTODY_MIN_SIGNER_THRESHOLD: u64 = 2;
pub const CUSTODY_MAX_SIGNERS: usize = 32;
pub const CUSTODY_STATUS_ACTIVE: &str = "active";
pub const CUSTODY_STATUS_PENDING: &str = "pending";
pub const CUSTODY_STATUS_EXECUTED: &str = "executed";
pub const CUSTODY_STATUS_FAILED: &str = "failed";
pub const CUSTODY_STATUS_RETIRED: &str = "retired";
pub const CUSTODY_STATUS_STUCK: &str = "stuck";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyWalletKind {
    Hot,
    Sweep,
    Reserve,
    Release,
    ViewOnlyObserver,
}

impl CustodyWalletKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Sweep => "sweep",
            Self::Reserve => "reserve",
            Self::Release => "release",
            Self::ViewOnlyObserver => "view_only_observer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyBatchKind {
    DepositSweep,
    WithdrawalRelease,
    FeeBump,
}

impl CustodyBatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositSweep => "deposit_sweep",
            Self::WithdrawalRelease => "withdrawal_release",
            Self::FeeBump => "fee_bump",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyEvidenceKind {
    MissingConfirmation,
    LowFee,
    ReorgRisk,
    SignerNonResponse,
    RpcDisagreement,
}

impl CustodyEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingConfirmation => "missing_confirmation",
            Self::LowFee => "low_fee",
            Self::ReorgRisk => "reorg_risk",
            Self::SignerNonResponse => "signer_non_response",
            Self::RpcDisagreement => "rpc_disagreement",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodySignerSet {
    pub signer_set_id: String,
    pub epoch: u64,
    pub threshold: u64,
    pub signer_commitments: Vec<String>,
    pub quantum_auth_root: String,
    pub monero_multisig_root: String,
    pub active_from_height: u64,
    pub active_until_height: Option<u64>,
    pub status: String,
}

impl CustodySignerSet {
    pub fn new(
        epoch: u64,
        threshold: u64,
        signer_commitments: Vec<String>,
        quantum_auth_root: impl Into<String>,
        monero_multisig_root: impl Into<String>,
        active_from_height: u64,
    ) -> CustodyResult<Self> {
        let quantum_auth_root = quantum_auth_root.into();
        let monero_multisig_root = monero_multisig_root.into();
        validate_threshold(threshold, signer_commitments.len())?;
        ensure_unique_strings(&signer_commitments, "custody signer commitments")?;
        ensure_non_empty(&quantum_auth_root, "custody quantum auth root")?;
        ensure_non_empty(&monero_multisig_root, "custody monero multisig root")?;
        let signer_set_id = custody_signer_set_id(
            epoch,
            threshold,
            &signer_commitments,
            &quantum_auth_root,
            &monero_multisig_root,
        );
        Ok(Self {
            signer_set_id,
            epoch,
            threshold,
            signer_commitments,
            quantum_auth_root,
            monero_multisig_root,
            active_from_height,
            active_until_height: None,
            status: CUSTODY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn retire_at(&mut self, height: u64) -> CustodyResult<()> {
        if height <= self.active_from_height {
            return Err("custody signer set retirement must be after activation".to_string());
        }
        self.active_until_height = Some(height);
        self.status = CUSTODY_STATUS_RETIRED.to_string();
        Ok(())
    }

    pub fn validate(&self) -> CustodyResult<()> {
        validate_threshold(self.threshold, self.signer_commitments.len())?;
        ensure_unique_strings(&self.signer_commitments, "custody signer commitments")?;
        ensure_non_empty(&self.quantum_auth_root, "custody quantum auth root")?;
        ensure_non_empty(&self.monero_multisig_root, "custody monero multisig root")?;
        if !matches!(
            self.status.as_str(),
            CUSTODY_STATUS_ACTIVE | CUSTODY_STATUS_RETIRED
        ) {
            return Err("custody signer set status is unknown".to_string());
        }
        if self.signer_set_id
            != custody_signer_set_id(
                self.epoch,
                self.threshold,
                &self.signer_commitments,
                &self.quantum_auth_root,
                &self.monero_multisig_root,
            )
        {
            return Err("custody signer set id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "custody_signer_set",
            "chain_id": CHAIN_ID,
            "protocol_version": CUSTODY_PROTOCOL_VERSION,
            "signer_set_id": self.signer_set_id,
            "epoch": self.epoch,
            "threshold": self.threshold,
            "signer_count": self.signer_commitments.len() as u64,
            "signer_commitment_root": custody_string_set_root("CUSTODY-SIGNER-COMMITMENTS", &self.signer_commitments),
            "quantum_auth_root": self.quantum_auth_root,
            "monero_multisig_root": self.monero_multisig_root,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveWallet {
    pub wallet_id: String,
    pub label: String,
    pub wallet_kind: CustodyWalletKind,
    pub address_hash: String,
    pub view_key_commitment: String,
    pub spend_authority_root: String,
    pub signer_set_id: String,
    pub created_at_height: u64,
    pub balance_floor_units: u64,
    pub status: String,
}

impl ReserveWallet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        wallet_kind: CustodyWalletKind,
        address_hash: impl Into<String>,
        view_key_commitment: impl Into<String>,
        spend_authority_root: impl Into<String>,
        signer_set_id: impl Into<String>,
        created_at_height: u64,
        balance_floor_units: u64,
    ) -> CustodyResult<Self> {
        let label = label.into();
        let address_hash = address_hash.into();
        let view_key_commitment = view_key_commitment.into();
        let spend_authority_root = spend_authority_root.into();
        let signer_set_id = signer_set_id.into();
        ensure_non_empty(&label, "custody reserve wallet label")?;
        ensure_non_empty(&address_hash, "custody reserve wallet address hash")?;
        ensure_non_empty(
            &view_key_commitment,
            "custody reserve wallet view key commitment",
        )?;
        ensure_non_empty(
            &spend_authority_root,
            "custody reserve wallet spend authority root",
        )?;
        ensure_non_empty(&signer_set_id, "custody reserve wallet signer set id")?;
        let wallet_id = reserve_wallet_id(
            &label,
            wallet_kind,
            &address_hash,
            &view_key_commitment,
            &spend_authority_root,
            &signer_set_id,
        );
        Ok(Self {
            wallet_id,
            label,
            wallet_kind,
            address_hash,
            view_key_commitment,
            spend_authority_root,
            signer_set_id,
            created_at_height,
            balance_floor_units,
            status: CUSTODY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_wallet",
            "chain_id": CHAIN_ID,
            "protocol_version": CUSTODY_PROTOCOL_VERSION,
            "wallet_id": self.wallet_id,
            "label": self.label,
            "wallet_kind": self.wallet_kind.as_str(),
            "address_hash": self.address_hash,
            "view_key_commitment": self.view_key_commitment,
            "spend_authority_root": self.spend_authority_root,
            "signer_set_id": self.signer_set_id,
            "created_at_height": self.created_at_height,
            "balance_floor_units": self.balance_floor_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewOnlyObserver {
    pub observer_id: String,
    pub label: String,
    pub wallet_id: String,
    pub view_key_commitment: String,
    pub endpoint_commitment: String,
    pub authorization_root: String,
    pub active: bool,
}

impl ViewOnlyObserver {
    pub fn new(
        label: impl Into<String>,
        wallet_id: impl Into<String>,
        view_key_commitment: impl Into<String>,
        endpoint_commitment: impl Into<String>,
        authorization_root: impl Into<String>,
    ) -> CustodyResult<Self> {
        let label = label.into();
        let wallet_id = wallet_id.into();
        let view_key_commitment = view_key_commitment.into();
        let endpoint_commitment = endpoint_commitment.into();
        let authorization_root = authorization_root.into();
        ensure_non_empty(&label, "custody observer label")?;
        ensure_non_empty(&wallet_id, "custody observer wallet id")?;
        ensure_non_empty(&view_key_commitment, "custody observer view key commitment")?;
        ensure_non_empty(&endpoint_commitment, "custody observer endpoint commitment")?;
        ensure_non_empty(&authorization_root, "custody observer authorization root")?;
        let observer_id = view_only_observer_id(
            &label,
            &wallet_id,
            &view_key_commitment,
            &endpoint_commitment,
            &authorization_root,
        );
        Ok(Self {
            observer_id,
            label,
            wallet_id,
            view_key_commitment,
            endpoint_commitment,
            authorization_root,
            active: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_only_observer",
            "chain_id": CHAIN_ID,
            "observer_id": self.observer_id,
            "label": self.label,
            "wallet_id": self.wallet_id,
            "view_key_commitment": self.view_key_commitment,
            "endpoint_commitment": self.endpoint_commitment,
            "authorization_root": self.authorization_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeBumpPolicy {
    pub policy_id: String,
    pub label: String,
    pub bump_interval_blocks: u64,
    pub multiplier_bps: u64,
    pub max_bump_units: u64,
    pub max_attempts: u64,
    pub status: String,
}

impl FeeBumpPolicy {
    pub fn conservative(label: impl Into<String>) -> CustodyResult<Self> {
        Self::new(
            label,
            CUSTODY_DEFAULT_FEE_BUMP_INTERVAL_BLOCKS,
            1_250,
            20,
            CUSTODY_DEFAULT_MAX_FEE_BUMP_ATTEMPTS,
        )
    }

    pub fn new(
        label: impl Into<String>,
        bump_interval_blocks: u64,
        multiplier_bps: u64,
        max_bump_units: u64,
        max_attempts: u64,
    ) -> CustodyResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "custody fee bump policy label")?;
        ensure_positive(bump_interval_blocks, "custody fee bump interval")?;
        ensure_positive(multiplier_bps, "custody fee bump multiplier")?;
        ensure_positive(max_attempts, "custody fee bump max attempts")?;
        let policy_id = fee_bump_policy_id(
            &label,
            bump_interval_blocks,
            multiplier_bps,
            max_bump_units,
            max_attempts,
        );
        Ok(Self {
            policy_id,
            label,
            bump_interval_blocks,
            multiplier_bps,
            max_bump_units,
            max_attempts,
            status: CUSTODY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_bump_policy",
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "label": self.label,
            "bump_interval_blocks": self.bump_interval_blocks,
            "multiplier_bps": self.multiplier_bps,
            "max_bump_units": self.max_bump_units,
            "max_attempts": self.max_attempts,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSweepBatch {
    pub sweep_id: String,
    pub deposit_ids: Vec<String>,
    pub source_address_root: String,
    pub destination_wallet_id: String,
    pub total_amount_units: u64,
    pub observed_txid_root: String,
    pub unlock_height: u64,
    pub requested_at_height: u64,
    pub fee_policy_id: String,
    pub signer_set_id: String,
    pub status: String,
}

impl DepositSweepBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deposit_ids: Vec<String>,
        source_address_hashes: Vec<String>,
        destination_wallet_id: impl Into<String>,
        total_amount_units: u64,
        observed_txid_hashes: Vec<String>,
        unlock_height: u64,
        requested_at_height: u64,
        fee_policy_id: impl Into<String>,
        signer_set_id: impl Into<String>,
    ) -> CustodyResult<Self> {
        let destination_wallet_id = destination_wallet_id.into();
        let fee_policy_id = fee_policy_id.into();
        let signer_set_id = signer_set_id.into();
        ensure_unique_strings(&deposit_ids, "custody sweep deposit ids")?;
        ensure_unique_strings(
            &source_address_hashes,
            "custody sweep source address hashes",
        )?;
        ensure_unique_strings(&observed_txid_hashes, "custody sweep observed txids")?;
        ensure_non_empty(
            &destination_wallet_id,
            "custody sweep destination wallet id",
        )?;
        ensure_non_empty(&fee_policy_id, "custody sweep fee policy id")?;
        ensure_non_empty(&signer_set_id, "custody sweep signer set id")?;
        ensure_positive(total_amount_units, "custody sweep total amount")?;
        if unlock_height < requested_at_height {
            return Err("custody sweep unlock height cannot precede request".to_string());
        }
        let source_address_root =
            custody_string_set_root("CUSTODY-SWEEP-SOURCE-ADDRESSES", &source_address_hashes);
        let observed_txid_root =
            custody_string_set_root("CUSTODY-SWEEP-OBSERVED-TXIDS", &observed_txid_hashes);
        let sweep_id = deposit_sweep_batch_id(
            &deposit_ids,
            &source_address_root,
            &destination_wallet_id,
            total_amount_units,
            &observed_txid_root,
            unlock_height,
            requested_at_height,
            &fee_policy_id,
            &signer_set_id,
        );
        Ok(Self {
            sweep_id,
            deposit_ids,
            source_address_root,
            destination_wallet_id,
            total_amount_units,
            observed_txid_root,
            unlock_height,
            requested_at_height,
            fee_policy_id,
            signer_set_id,
            status: CUSTODY_STATUS_PENDING.to_string(),
        })
    }

    pub fn mark_executed(&mut self) {
        self.status = CUSTODY_STATUS_EXECUTED.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deposit_sweep_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": CUSTODY_PROTOCOL_VERSION,
            "sweep_id": self.sweep_id,
            "deposit_root": custody_string_set_root("CUSTODY-SWEEP-DEPOSITS", &self.deposit_ids),
            "deposit_count": self.deposit_ids.len() as u64,
            "source_address_root": self.source_address_root,
            "destination_wallet_id": self.destination_wallet_id,
            "total_amount_units": self.total_amount_units,
            "observed_txid_root": self.observed_txid_root,
            "unlock_height": self.unlock_height,
            "requested_at_height": self.requested_at_height,
            "fee_policy_id": self.fee_policy_id,
            "signer_set_id": self.signer_set_id,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalReleaseBatch {
    pub release_id: String,
    pub withdrawal_ids: Vec<String>,
    pub reserve_wallet_id: String,
    pub recipient_address_root: String,
    pub total_amount_units: u64,
    pub fee_units: u64,
    pub created_at_height: u64,
    pub unlock_height: u64,
    pub signer_set_id: String,
    pub signature_root: String,
    pub release_txid_hash: Option<String>,
    pub status: String,
}

impl WithdrawalReleaseBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_ids: Vec<String>,
        reserve_wallet_id: impl Into<String>,
        recipient_address_hashes: Vec<String>,
        total_amount_units: u64,
        fee_units: u64,
        created_at_height: u64,
        unlock_height: u64,
        signer_set_id: impl Into<String>,
        signature_root: impl Into<String>,
    ) -> CustodyResult<Self> {
        let reserve_wallet_id = reserve_wallet_id.into();
        let signer_set_id = signer_set_id.into();
        let signature_root = signature_root.into();
        ensure_unique_strings(&withdrawal_ids, "custody withdrawal ids")?;
        ensure_unique_strings(
            &recipient_address_hashes,
            "custody recipient address hashes",
        )?;
        ensure_non_empty(&reserve_wallet_id, "custody release reserve wallet id")?;
        ensure_non_empty(&signer_set_id, "custody release signer set id")?;
        ensure_non_empty(&signature_root, "custody release signature root")?;
        ensure_positive(total_amount_units, "custody release total amount")?;
        if unlock_height < created_at_height {
            return Err("custody release unlock height cannot precede creation".to_string());
        }
        let recipient_address_root = custody_string_set_root(
            "CUSTODY-RELEASE-RECIPIENT-ADDRESSES",
            &recipient_address_hashes,
        );
        let release_id = withdrawal_release_batch_id(
            &withdrawal_ids,
            &reserve_wallet_id,
            &recipient_address_root,
            total_amount_units,
            fee_units,
            created_at_height,
            unlock_height,
            &signer_set_id,
            &signature_root,
        );
        Ok(Self {
            release_id,
            withdrawal_ids,
            reserve_wallet_id,
            recipient_address_root,
            total_amount_units,
            fee_units,
            created_at_height,
            unlock_height,
            signer_set_id,
            signature_root,
            release_txid_hash: None,
            status: CUSTODY_STATUS_PENDING.to_string(),
        })
    }

    pub fn attach_release_tx(&mut self, txid_hash: impl Into<String>) -> CustodyResult<String> {
        let txid_hash = txid_hash.into();
        ensure_non_empty(&txid_hash, "custody release txid hash")?;
        self.release_txid_hash = Some(txid_hash);
        self.status = CUSTODY_STATUS_EXECUTED.to_string();
        Ok(self.release_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "withdrawal_release_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": CUSTODY_PROTOCOL_VERSION,
            "release_id": self.release_id,
            "withdrawal_root": custody_string_set_root("CUSTODY-RELEASE-WITHDRAWALS", &self.withdrawal_ids),
            "withdrawal_count": self.withdrawal_ids.len() as u64,
            "reserve_wallet_id": self.reserve_wallet_id,
            "recipient_address_root": self.recipient_address_root,
            "total_amount_units": self.total_amount_units,
            "fee_units": self.fee_units,
            "created_at_height": self.created_at_height,
            "unlock_height": self.unlock_height,
            "signer_set_id": self.signer_set_id,
            "signature_root": self.signature_root,
            "release_txid_hash": self.release_txid_hash,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProof {
    pub proof_id: String,
    pub height: u64,
    pub reserve_wallet_root: String,
    pub observer_root: String,
    pub total_observed_units: u64,
    pub total_liability_units: u64,
    pub proof_system: String,
    pub proof_commitment: String,
    pub status: String,
}

impl ReserveProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        reserve_wallet_root: impl Into<String>,
        observer_root: impl Into<String>,
        total_observed_units: u64,
        total_liability_units: u64,
        proof_system: impl Into<String>,
        proof_commitment: impl Into<String>,
    ) -> CustodyResult<Self> {
        let reserve_wallet_root = reserve_wallet_root.into();
        let observer_root = observer_root.into();
        let proof_system = proof_system.into();
        let proof_commitment = proof_commitment.into();
        ensure_non_empty(&reserve_wallet_root, "custody reserve proof wallet root")?;
        ensure_non_empty(&observer_root, "custody reserve proof observer root")?;
        ensure_non_empty(&proof_system, "custody reserve proof system")?;
        ensure_non_empty(&proof_commitment, "custody reserve proof commitment")?;
        if total_observed_units < total_liability_units {
            return Err("custody reserve proof is undercollateralized".to_string());
        }
        let proof_id = reserve_proof_id(
            height,
            &reserve_wallet_root,
            &observer_root,
            total_observed_units,
            total_liability_units,
            &proof_system,
            &proof_commitment,
        );
        Ok(Self {
            proof_id,
            height,
            reserve_wallet_root,
            observer_root,
            total_observed_units,
            total_liability_units,
            proof_system,
            proof_commitment,
            status: CUSTODY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn excess_reserve_units(&self) -> u64 {
        self.total_observed_units
            .saturating_sub(self.total_liability_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": CUSTODY_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "height": self.height,
            "reserve_wallet_root": self.reserve_wallet_root,
            "observer_root": self.observer_root,
            "total_observed_units": self.total_observed_units,
            "total_liability_units": self.total_liability_units,
            "excess_reserve_units": self.excess_reserve_units(),
            "proof_system": self.proof_system,
            "proof_commitment": self.proof_commitment,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerRotation {
    pub rotation_id: String,
    pub old_signer_set_id: String,
    pub new_signer_set_id: String,
    pub effective_height: u64,
    pub reason_root: String,
    pub authorized_by_root: String,
    pub status: String,
}

impl SignerRotation {
    pub fn new(
        old_signer_set_id: impl Into<String>,
        new_signer_set_id: impl Into<String>,
        effective_height: u64,
        reason_root: impl Into<String>,
        authorized_by_root: impl Into<String>,
    ) -> CustodyResult<Self> {
        let old_signer_set_id = old_signer_set_id.into();
        let new_signer_set_id = new_signer_set_id.into();
        let reason_root = reason_root.into();
        let authorized_by_root = authorized_by_root.into();
        ensure_non_empty(&old_signer_set_id, "custody rotation old signer set id")?;
        ensure_non_empty(&new_signer_set_id, "custody rotation new signer set id")?;
        ensure_non_empty(&reason_root, "custody rotation reason root")?;
        ensure_non_empty(&authorized_by_root, "custody rotation authorization root")?;
        if old_signer_set_id == new_signer_set_id {
            return Err("custody signer rotation requires a new signer set".to_string());
        }
        let rotation_id = signer_rotation_id(
            &old_signer_set_id,
            &new_signer_set_id,
            effective_height,
            &reason_root,
            &authorized_by_root,
        );
        Ok(Self {
            rotation_id,
            old_signer_set_id,
            new_signer_set_id,
            effective_height,
            reason_root,
            authorized_by_root,
            status: CUSTODY_STATUS_PENDING.to_string(),
        })
    }

    pub fn activate(&mut self) {
        self.status = CUSTODY_STATUS_EXECUTED.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "signer_rotation",
            "chain_id": CHAIN_ID,
            "rotation_id": self.rotation_id,
            "old_signer_set_id": self.old_signer_set_id,
            "new_signer_set_id": self.new_signer_set_id,
            "effective_height": self.effective_height,
            "reason_root": self.reason_root,
            "authorized_by_root": self.authorized_by_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StuckTxEvidence {
    pub evidence_id: String,
    pub subject_id: String,
    pub txid_hash: String,
    pub evidence_kind: CustodyEvidenceKind,
    pub first_seen_height: u64,
    pub last_seen_height: u64,
    pub fee_units: u64,
    pub recommended_bump_units: u64,
    pub observer_root: String,
    pub status: String,
}

impl StuckTxEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        txid_hash: impl Into<String>,
        evidence_kind: CustodyEvidenceKind,
        first_seen_height: u64,
        last_seen_height: u64,
        fee_units: u64,
        recommended_bump_units: u64,
        observer_root: impl Into<String>,
    ) -> CustodyResult<Self> {
        let subject_id = subject_id.into();
        let txid_hash = txid_hash.into();
        let observer_root = observer_root.into();
        ensure_non_empty(&subject_id, "custody stuck tx subject id")?;
        ensure_non_empty(&txid_hash, "custody stuck tx hash")?;
        ensure_non_empty(&observer_root, "custody stuck tx observer root")?;
        if last_seen_height < first_seen_height {
            return Err("custody stuck tx last seen cannot precede first seen".to_string());
        }
        let evidence_id = stuck_tx_evidence_id(
            &subject_id,
            &txid_hash,
            evidence_kind,
            first_seen_height,
            last_seen_height,
            fee_units,
            recommended_bump_units,
            &observer_root,
        );
        Ok(Self {
            evidence_id,
            subject_id,
            txid_hash,
            evidence_kind,
            first_seen_height,
            last_seen_height,
            fee_units,
            recommended_bump_units,
            observer_root,
            status: CUSTODY_STATUS_STUCK.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stuck_tx_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "subject_id": self.subject_id,
            "txid_hash": self.txid_hash,
            "evidence_kind": self.evidence_kind.as_str(),
            "first_seen_height": self.first_seen_height,
            "last_seen_height": self.last_seen_height,
            "fee_units": self.fee_units,
            "recommended_bump_units": self.recommended_bump_units,
            "observer_root": self.observer_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAuditEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub actor_commitment: String,
    pub height: u64,
    pub record_root: String,
    pub status: String,
}

impl CustodyAuditEvent {
    pub fn new(
        event_kind: impl Into<String>,
        subject_id: impl Into<String>,
        actor_commitment: impl Into<String>,
        height: u64,
        record_root: impl Into<String>,
        status: impl Into<String>,
    ) -> CustodyResult<Self> {
        let event_kind = event_kind.into();
        let subject_id = subject_id.into();
        let actor_commitment = actor_commitment.into();
        let record_root = record_root.into();
        let status = status.into();
        ensure_non_empty(&event_kind, "custody audit event kind")?;
        ensure_non_empty(&subject_id, "custody audit subject id")?;
        ensure_non_empty(&actor_commitment, "custody audit actor commitment")?;
        ensure_non_empty(&record_root, "custody audit record root")?;
        ensure_non_empty(&status, "custody audit status")?;
        let event_id = custody_audit_event_id(
            &event_kind,
            &subject_id,
            &actor_commitment,
            height,
            &record_root,
            &status,
        );
        Ok(Self {
            event_id,
            event_kind,
            subject_id,
            actor_commitment,
            height,
            record_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "custody_audit_event",
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "actor_commitment": self.actor_commitment,
            "height": self.height,
            "record_root": self.record_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyState {
    pub height: u64,
    pub signer_sets: Vec<CustodySignerSet>,
    pub reserve_wallets: Vec<ReserveWallet>,
    pub observers: Vec<ViewOnlyObserver>,
    pub fee_policies: Vec<FeeBumpPolicy>,
    pub sweep_batches: Vec<DepositSweepBatch>,
    pub release_batches: Vec<WithdrawalReleaseBatch>,
    pub reserve_proofs: Vec<ReserveProof>,
    pub rotations: Vec<SignerRotation>,
    pub stuck_evidence: Vec<StuckTxEvidence>,
    pub audit_events: Vec<CustodyAuditEvent>,
}

impl CustodyState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            signer_sets: Vec::new(),
            reserve_wallets: Vec::new(),
            observers: Vec::new(),
            fee_policies: Vec::new(),
            sweep_batches: Vec::new(),
            release_batches: Vec::new(),
            reserve_proofs: Vec::new(),
            rotations: Vec::new(),
            stuck_evidence: Vec::new(),
            audit_events: Vec::new(),
        }
    }

    pub fn devnet(operator_label: &str) -> CustodyResult<Self> {
        ensure_non_empty(operator_label, "custody devnet operator label")?;
        let mut state = Self::new(0);
        let signer_commitments = vec![
            custody_label_commitment(operator_label, "signer-a"),
            custody_label_commitment(operator_label, "signer-b"),
            custody_label_commitment(operator_label, "signer-c"),
        ];
        let signer_set = CustodySignerSet::new(
            0,
            2,
            signer_commitments,
            custody_label_commitment(operator_label, "ml-dsa-signer-root"),
            custody_label_commitment(operator_label, "monero-multisig-root"),
            0,
        )?;
        let wallet = ReserveWallet::new(
            "devnet-reserve",
            CustodyWalletKind::Reserve,
            custody_label_commitment(operator_label, "reserve-address"),
            custody_label_commitment(operator_label, "view-key"),
            custody_label_commitment(operator_label, "spend-authority"),
            signer_set.signer_set_id.clone(),
            0,
            1_000,
        )?;
        let observer = ViewOnlyObserver::new(
            "devnet-observer",
            wallet.wallet_id.clone(),
            wallet.view_key_commitment.clone(),
            custody_label_commitment(operator_label, "monero-rpc"),
            custody_label_commitment(operator_label, "observer-auth"),
        )?;
        let fee_policy = FeeBumpPolicy::conservative("devnet-fee-bump")?;

        state.add_signer_set(signer_set, operator_label)?;
        state.add_reserve_wallet(wallet, operator_label)?;
        state.add_observer(observer, operator_label)?;
        state.add_fee_policy(fee_policy, operator_label)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn add_signer_set(
        &mut self,
        signer_set: CustodySignerSet,
        actor: &str,
    ) -> CustodyResult<String> {
        signer_set.validate()?;
        let record_root =
            custody_payload_root("CUSTODY-AUDIT-SIGNER-SET", &signer_set.public_record());
        let signer_set_id = signer_set.signer_set_id.clone();
        self.signer_sets.push(signer_set);
        self.audit("signer_set_added", &signer_set_id, actor, record_root)?;
        Ok(signer_set_id)
    }

    pub fn add_reserve_wallet(
        &mut self,
        wallet: ReserveWallet,
        actor: &str,
    ) -> CustodyResult<String> {
        ensure_non_empty(&wallet.signer_set_id, "custody wallet signer set id")?;
        let record_root = custody_payload_root("CUSTODY-AUDIT-WALLET", &wallet.public_record());
        let wallet_id = wallet.wallet_id.clone();
        self.reserve_wallets.push(wallet);
        self.audit("reserve_wallet_added", &wallet_id, actor, record_root)?;
        Ok(wallet_id)
    }

    pub fn add_observer(
        &mut self,
        observer: ViewOnlyObserver,
        actor: &str,
    ) -> CustodyResult<String> {
        let record_root = custody_payload_root("CUSTODY-AUDIT-OBSERVER", &observer.public_record());
        let observer_id = observer.observer_id.clone();
        self.observers.push(observer);
        self.audit("observer_added", &observer_id, actor, record_root)?;
        Ok(observer_id)
    }

    pub fn add_fee_policy(&mut self, policy: FeeBumpPolicy, actor: &str) -> CustodyResult<String> {
        let record_root = custody_payload_root("CUSTODY-AUDIT-FEE-POLICY", &policy.public_record());
        let policy_id = policy.policy_id.clone();
        self.fee_policies.push(policy);
        self.audit("fee_policy_added", &policy_id, actor, record_root)?;
        Ok(policy_id)
    }

    pub fn queue_sweep(&mut self, sweep: DepositSweepBatch, actor: &str) -> CustodyResult<String> {
        let record_root = custody_payload_root("CUSTODY-AUDIT-SWEEP", &sweep.public_record());
        let sweep_id = sweep.sweep_id.clone();
        self.sweep_batches.push(sweep);
        self.audit("sweep_queued", &sweep_id, actor, record_root)?;
        Ok(sweep_id)
    }

    pub fn queue_release(
        &mut self,
        release: WithdrawalReleaseBatch,
        actor: &str,
    ) -> CustodyResult<String> {
        let record_root = custody_payload_root("CUSTODY-AUDIT-RELEASE", &release.public_record());
        let release_id = release.release_id.clone();
        self.release_batches.push(release);
        self.audit("release_queued", &release_id, actor, record_root)?;
        Ok(release_id)
    }

    pub fn publish_reserve_proof(
        &mut self,
        proof: ReserveProof,
        actor: &str,
    ) -> CustodyResult<String> {
        let record_root =
            custody_payload_root("CUSTODY-AUDIT-RESERVE-PROOF", &proof.public_record());
        let proof_id = proof.proof_id.clone();
        self.reserve_proofs.push(proof);
        self.audit("reserve_proof_published", &proof_id, actor, record_root)?;
        Ok(proof_id)
    }

    pub fn record_rotation(
        &mut self,
        rotation: SignerRotation,
        actor: &str,
    ) -> CustodyResult<String> {
        let record_root = custody_payload_root("CUSTODY-AUDIT-ROTATION", &rotation.public_record());
        let rotation_id = rotation.rotation_id.clone();
        self.rotations.push(rotation);
        self.audit("signer_rotation_recorded", &rotation_id, actor, record_root)?;
        Ok(rotation_id)
    }

    pub fn record_stuck_tx(
        &mut self,
        evidence: StuckTxEvidence,
        actor: &str,
    ) -> CustodyResult<String> {
        let record_root = custody_payload_root("CUSTODY-AUDIT-STUCK-TX", &evidence.public_record());
        let evidence_id = evidence.evidence_id.clone();
        self.stuck_evidence.push(evidence);
        self.audit("stuck_tx_recorded", &evidence_id, actor, record_root)?;
        Ok(evidence_id)
    }

    pub fn active_signer_set(&self) -> Option<&CustodySignerSet> {
        self.signer_sets
            .iter()
            .rev()
            .find(|signer_set| signer_set.status == CUSTODY_STATUS_ACTIVE)
    }

    pub fn reserve_wallet_root(&self) -> String {
        reserve_wallet_root(&self.reserve_wallets)
    }

    pub fn observer_root(&self) -> String {
        view_only_observer_root(&self.observers)
    }

    pub fn state_root(&self) -> String {
        custody_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "custody_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CUSTODY_PROTOCOL_VERSION,
            "height": self.height,
            "signer_set_root": custody_signer_set_root(&self.signer_sets),
            "reserve_wallet_root": reserve_wallet_root(&self.reserve_wallets),
            "observer_root": view_only_observer_root(&self.observers),
            "fee_policy_root": fee_bump_policy_root(&self.fee_policies),
            "sweep_batch_root": deposit_sweep_batch_root(&self.sweep_batches),
            "release_batch_root": withdrawal_release_batch_root(&self.release_batches),
            "reserve_proof_root": reserve_proof_root(&self.reserve_proofs),
            "rotation_root": signer_rotation_root(&self.rotations),
            "stuck_evidence_root": stuck_tx_evidence_root(&self.stuck_evidence),
            "audit_root": custody_audit_event_root(&self.audit_events),
            "signer_set_count": self.signer_sets.len() as u64,
            "reserve_wallet_count": self.reserve_wallets.len() as u64,
            "observer_count": self.observers.len() as u64,
            "pending_sweep_count": self.sweep_batches.iter().filter(|batch| batch.status == CUSTODY_STATUS_PENDING).count() as u64,
            "pending_release_count": self.release_batches.iter().filter(|batch| batch.status == CUSTODY_STATUS_PENDING).count() as u64,
        })
    }

    fn audit(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        actor: &str,
        record_root: String,
    ) -> CustodyResult<String> {
        let event = CustodyAuditEvent::new(
            event_kind,
            subject_id,
            custody_label_commitment(actor, "custody-actor"),
            self.height,
            record_root,
            CUSTODY_STATUS_EXECUTED,
        )?;
        let event_id = event.event_id.clone();
        self.audit_events.push(event);
        Ok(event_id)
    }
}

pub fn custody_label_commitment(operator_label: &str, label: &str) -> String {
    domain_hash(
        "CUSTODY-LABEL-COMMITMENT",
        &[HashPart::Str(operator_label), HashPart::Str(label)],
        32,
    )
}

pub fn custody_signer_set_id(
    epoch: u64,
    threshold: u64,
    signer_commitments: &[String],
    quantum_auth_root: &str,
    monero_multisig_root: &str,
) -> String {
    domain_hash(
        "CUSTODY-SIGNER-SET-ID",
        &[
            HashPart::Int(epoch as i128),
            HashPart::Int(threshold as i128),
            HashPart::Str(&custody_string_set_root(
                "CUSTODY-SIGNER-SET-SIGNERS",
                signer_commitments,
            )),
            HashPart::Str(quantum_auth_root),
            HashPart::Str(monero_multisig_root),
        ],
        32,
    )
}

pub fn reserve_wallet_id(
    label: &str,
    wallet_kind: CustodyWalletKind,
    address_hash: &str,
    view_key_commitment: &str,
    spend_authority_root: &str,
    signer_set_id: &str,
) -> String {
    domain_hash(
        "CUSTODY-RESERVE-WALLET-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(wallet_kind.as_str()),
            HashPart::Str(address_hash),
            HashPart::Str(view_key_commitment),
            HashPart::Str(spend_authority_root),
            HashPart::Str(signer_set_id),
        ],
        32,
    )
}

pub fn view_only_observer_id(
    label: &str,
    wallet_id: &str,
    view_key_commitment: &str,
    endpoint_commitment: &str,
    authorization_root: &str,
) -> String {
    domain_hash(
        "CUSTODY-VIEW-ONLY-OBSERVER-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(wallet_id),
            HashPart::Str(view_key_commitment),
            HashPart::Str(endpoint_commitment),
            HashPart::Str(authorization_root),
        ],
        32,
    )
}

pub fn fee_bump_policy_id(
    label: &str,
    bump_interval_blocks: u64,
    multiplier_bps: u64,
    max_bump_units: u64,
    max_attempts: u64,
) -> String {
    domain_hash(
        "CUSTODY-FEE-BUMP-POLICY-ID",
        &[
            HashPart::Str(label),
            HashPart::Int(bump_interval_blocks as i128),
            HashPart::Int(multiplier_bps as i128),
            HashPart::Int(max_bump_units as i128),
            HashPart::Int(max_attempts as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn deposit_sweep_batch_id(
    deposit_ids: &[String],
    source_address_root: &str,
    destination_wallet_id: &str,
    total_amount_units: u64,
    observed_txid_root: &str,
    unlock_height: u64,
    requested_at_height: u64,
    fee_policy_id: &str,
    signer_set_id: &str,
) -> String {
    domain_hash(
        "CUSTODY-DEPOSIT-SWEEP-BATCH-ID",
        &[
            HashPart::Str(&custody_string_set_root(
                "CUSTODY-SWEEP-ID-DEPOSITS",
                deposit_ids,
            )),
            HashPart::Str(source_address_root),
            HashPart::Str(destination_wallet_id),
            HashPart::Int(total_amount_units as i128),
            HashPart::Str(observed_txid_root),
            HashPart::Int(unlock_height as i128),
            HashPart::Int(requested_at_height as i128),
            HashPart::Str(fee_policy_id),
            HashPart::Str(signer_set_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn withdrawal_release_batch_id(
    withdrawal_ids: &[String],
    reserve_wallet_id: &str,
    recipient_address_root: &str,
    total_amount_units: u64,
    fee_units: u64,
    created_at_height: u64,
    unlock_height: u64,
    signer_set_id: &str,
    signature_root: &str,
) -> String {
    domain_hash(
        "CUSTODY-WITHDRAWAL-RELEASE-BATCH-ID",
        &[
            HashPart::Str(&custody_string_set_root(
                "CUSTODY-RELEASE-ID-WITHDRAWALS",
                withdrawal_ids,
            )),
            HashPart::Str(reserve_wallet_id),
            HashPart::Str(recipient_address_root),
            HashPart::Int(total_amount_units as i128),
            HashPart::Int(fee_units as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(unlock_height as i128),
            HashPart::Str(signer_set_id),
            HashPart::Str(signature_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reserve_proof_id(
    height: u64,
    reserve_wallet_root: &str,
    observer_root: &str,
    total_observed_units: u64,
    total_liability_units: u64,
    proof_system: &str,
    proof_commitment: &str,
) -> String {
    domain_hash(
        "CUSTODY-RESERVE-PROOF-ID",
        &[
            HashPart::Int(height as i128),
            HashPart::Str(reserve_wallet_root),
            HashPart::Str(observer_root),
            HashPart::Int(total_observed_units as i128),
            HashPart::Int(total_liability_units as i128),
            HashPart::Str(proof_system),
            HashPart::Str(proof_commitment),
        ],
        32,
    )
}

pub fn signer_rotation_id(
    old_signer_set_id: &str,
    new_signer_set_id: &str,
    effective_height: u64,
    reason_root: &str,
    authorized_by_root: &str,
) -> String {
    domain_hash(
        "CUSTODY-SIGNER-ROTATION-ID",
        &[
            HashPart::Str(old_signer_set_id),
            HashPart::Str(new_signer_set_id),
            HashPart::Int(effective_height as i128),
            HashPart::Str(reason_root),
            HashPart::Str(authorized_by_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn stuck_tx_evidence_id(
    subject_id: &str,
    txid_hash: &str,
    evidence_kind: CustodyEvidenceKind,
    first_seen_height: u64,
    last_seen_height: u64,
    fee_units: u64,
    recommended_bump_units: u64,
    observer_root: &str,
) -> String {
    domain_hash(
        "CUSTODY-STUCK-TX-EVIDENCE-ID",
        &[
            HashPart::Str(subject_id),
            HashPart::Str(txid_hash),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Int(first_seen_height as i128),
            HashPart::Int(last_seen_height as i128),
            HashPart::Int(fee_units as i128),
            HashPart::Int(recommended_bump_units as i128),
            HashPart::Str(observer_root),
        ],
        32,
    )
}

pub fn custody_audit_event_id(
    event_kind: &str,
    subject_id: &str,
    actor_commitment: &str,
    height: u64,
    record_root: &str,
    status: &str,
) -> String {
    domain_hash(
        "CUSTODY-AUDIT-EVENT-ID",
        &[
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(actor_commitment),
            HashPart::Int(height as i128),
            HashPart::Str(record_root),
            HashPart::Str(status),
        ],
        32,
    )
}

pub fn custody_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn custody_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn custody_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn custody_signer_set_root(values: &[CustodySignerSet]) -> String {
    let leaves = values
        .iter()
        .map(CustodySignerSet::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-SIGNER-SET-ROOT", &leaves)
}

pub fn reserve_wallet_root(values: &[ReserveWallet]) -> String {
    let leaves = values
        .iter()
        .map(ReserveWallet::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-RESERVE-WALLET-ROOT", &leaves)
}

pub fn view_only_observer_root(values: &[ViewOnlyObserver]) -> String {
    let leaves = values
        .iter()
        .map(ViewOnlyObserver::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-VIEW-ONLY-OBSERVER-ROOT", &leaves)
}

pub fn fee_bump_policy_root(values: &[FeeBumpPolicy]) -> String {
    let leaves = values
        .iter()
        .map(FeeBumpPolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-FEE-BUMP-POLICY-ROOT", &leaves)
}

pub fn deposit_sweep_batch_root(values: &[DepositSweepBatch]) -> String {
    let leaves = values
        .iter()
        .map(DepositSweepBatch::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-DEPOSIT-SWEEP-BATCH-ROOT", &leaves)
}

pub fn withdrawal_release_batch_root(values: &[WithdrawalReleaseBatch]) -> String {
    let leaves = values
        .iter()
        .map(WithdrawalReleaseBatch::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-WITHDRAWAL-RELEASE-BATCH-ROOT", &leaves)
}

pub fn reserve_proof_root(values: &[ReserveProof]) -> String {
    let leaves = values
        .iter()
        .map(ReserveProof::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-RESERVE-PROOF-ROOT", &leaves)
}

pub fn signer_rotation_root(values: &[SignerRotation]) -> String {
    let leaves = values
        .iter()
        .map(SignerRotation::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-SIGNER-ROTATION-ROOT", &leaves)
}

pub fn stuck_tx_evidence_root(values: &[StuckTxEvidence]) -> String {
    let leaves = values
        .iter()
        .map(StuckTxEvidence::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-STUCK-TX-EVIDENCE-ROOT", &leaves)
}

pub fn custody_audit_event_root(values: &[CustodyAuditEvent]) -> String {
    let leaves = values
        .iter()
        .map(CustodyAuditEvent::public_record)
        .collect::<Vec<_>>();
    merkle_root("CUSTODY-AUDIT-EVENT-ROOT", &leaves)
}

pub fn custody_state_root_from_record(record: &Value) -> String {
    custody_payload_root("CUSTODY-STATE-ROOT", record)
}

fn validate_threshold(threshold: u64, signer_count: usize) -> CustodyResult<()> {
    if threshold < CUSTODY_MIN_SIGNER_THRESHOLD {
        return Err("custody signer threshold is too low".to_string());
    }
    if signer_count > CUSTODY_MAX_SIGNERS {
        return Err("custody signer set exceeds max signer count".to_string());
    }
    if threshold as usize > signer_count {
        return Err("custody signer threshold exceeds signer count".to_string());
    }
    Ok(())
}

fn ensure_non_empty(value: &str, field: &str) -> CustodyResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> CustodyResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], field: &str) -> CustodyResult<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value"));
        }
    }
    Ok(())
}
