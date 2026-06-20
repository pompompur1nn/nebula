use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivatePqCrossContractAccountRecoveryResult<T> = Result<T, String>;

pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_PROTOCOL_VERSION: &str =
    "private-pq-cross-contract-account-recovery-v1";
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_HASH_SUITE: &str = "shake256-domain-v1";
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_AUTH_SUITE: &str =
    "ml-dsa-65+slh-dsa-shake-128s";
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_DEFAULT_EXECUTION_DELAY_BLOCKS: u64 = 4;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_DEFAULT_CHALLENGE_BLOCKS: u64 = 18;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_DOMAINS: usize = 32;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_GUARDIAN_SETS: usize = 128;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_INTENTS: usize = 512;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_ATTESTATIONS: usize = 2048;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_RECEIPTS: usize = 512;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_CHALLENGES: usize = 256;
pub const PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryDomainKind {
    SmartAccount,
    ContractWallet,
    PrivateVault,
    CrossRollupSafe,
    MoneroLinkedSpendAuthority,
}

impl RecoveryDomainKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SmartAccount => "smart_account",
            Self::ContractWallet => "contract_wallet",
            Self::PrivateVault => "private_vault",
            Self::CrossRollupSafe => "cross_rollup_safe",
            Self::MoneroLinkedSpendAuthority => "monero_linked_spend_authority",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryIntentStatus {
    Open,
    Attested,
    Ready,
    Executed,
    Expired,
    Cancelled,
    Challenged,
}

impl RecoveryIntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GuardianAttestationStatus {
    Pending,
    Accepted,
    Rejected,
    Slashed,
}

impl GuardianAttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryChallengeStatus {
    Open,
    Upheld,
    Rejected,
    Expired,
}

impl RecoveryChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDomain {
    pub domain_id: String,
    pub kind: RecoveryDomainKind,
    pub contract_root: String,
    pub policy_root: String,
    pub monero_anchor_hint: String,
    pub low_fee_budget_micro_units: u64,
    pub active: bool,
}

impl RecoveryDomain {
    pub fn new(
        domain_id: &str,
        kind: RecoveryDomainKind,
        contract_root: &str,
        policy_root: &str,
        monero_anchor_hint: &str,
        low_fee_budget_micro_units: u64,
    ) -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        let domain = Self {
            domain_id: domain_id.to_string(),
            kind,
            contract_root: contract_root.to_string(),
            policy_root: policy_root.to_string(),
            monero_anchor_hint: monero_anchor_hint.to_string(),
            low_fee_budget_micro_units,
            active: true,
        };
        domain.validate()?;
        Ok(domain)
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.domain_id.trim().is_empty() {
            return Err("recovery domain id cannot be empty".to_string());
        }
        if self.contract_root.trim().is_empty() {
            return Err("recovery domain contract root cannot be empty".to_string());
        }
        if self.policy_root.trim().is_empty() {
            return Err("recovery domain policy root cannot be empty".to_string());
        }
        if self.monero_anchor_hint.trim().is_empty() {
            return Err("recovery domain monero anchor hint cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_cross_contract_recovery_domain",
            "domain_id": self.domain_id,
            "domain_kind": self.kind.as_str(),
            "contract_root": self.contract_root,
            "policy_root": self.policy_root,
            "monero_anchor_hint": self.monero_anchor_hint,
            "low_fee_budget_micro_units": self.low_fee_budget_micro_units,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_pq_cross_contract_account_recovery_payload_root("DOMAIN", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSet {
    pub guardian_set_id: String,
    pub domain_id: String,
    pub guardian_commitments: BTreeSet<String>,
    pub pq_quorum_threshold: u64,
    pub stake_commitment_root: String,
    pub rotation_epoch: u64,
    pub active: bool,
}

impl GuardianSet {
    pub fn new(
        domain_id: &str,
        guardian_commitments: BTreeSet<String>,
        pq_quorum_threshold: u64,
        stake_commitment_root: &str,
        rotation_epoch: u64,
    ) -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        let guardian_set_id = private_pq_cross_contract_account_recovery_id(
            "GUARDIAN-SET",
            &[
                domain_id,
                stake_commitment_root,
                &rotation_epoch.to_string(),
                &private_pq_cross_contract_account_recovery_string_set_root(
                    "GUARDIAN-COMMITMENTS-ID",
                    &guardian_commitments.iter().cloned().collect::<Vec<_>>(),
                ),
            ],
        );
        let set = Self {
            guardian_set_id,
            domain_id: domain_id.to_string(),
            guardian_commitments,
            pq_quorum_threshold,
            stake_commitment_root: stake_commitment_root.to_string(),
            rotation_epoch,
            active: true,
        };
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.guardian_set_id.trim().is_empty() || self.domain_id.trim().is_empty() {
            return Err("guardian set ids cannot be empty".to_string());
        }
        if self.guardian_commitments.is_empty() {
            return Err("guardian set cannot be empty".to_string());
        }
        if self.pq_quorum_threshold == 0
            || self.pq_quorum_threshold > self.guardian_commitments.len() as u64
        {
            return Err("guardian quorum threshold is invalid".to_string());
        }
        if self.stake_commitment_root.trim().is_empty() {
            return Err("guardian stake root cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_cross_contract_guardian_set",
            "guardian_set_id": self.guardian_set_id,
            "domain_id": self.domain_id,
            "guardian_commitments": self.guardian_commitments.iter().cloned().collect::<Vec<_>>(),
            "pq_quorum_threshold": self.pq_quorum_threshold,
            "stake_commitment_root": self.stake_commitment_root,
            "rotation_epoch": self.rotation_epoch,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_pq_cross_contract_account_recovery_payload_root(
            "GUARDIAN-SET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryIntent {
    pub intent_id: String,
    pub domain_id: String,
    pub guardian_set_id: String,
    pub account_commitment: String,
    pub recovery_secret_commitment: String,
    pub new_authority_commitment: String,
    pub privacy_nullifier: String,
    pub encrypted_recovery_payload_root: String,
    pub fee_sponsor_commitment: String,
    pub opened_height: u64,
    pub ready_height: u64,
    pub expiry_height: u64,
    pub status: RecoveryIntentStatus,
}

impl RecoveryIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain_id: &str,
        guardian_set_id: &str,
        account_commitment: &str,
        recovery_secret_commitment: &str,
        new_authority_commitment: &str,
        privacy_nullifier: &str,
        encrypted_recovery_payload_root: &str,
        fee_sponsor_commitment: &str,
        opened_height: u64,
        execution_delay_blocks: u64,
        ttl_blocks: u64,
    ) -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        let intent_id = private_pq_cross_contract_account_recovery_id(
            "INTENT",
            &[
                domain_id,
                guardian_set_id,
                account_commitment,
                new_authority_commitment,
                privacy_nullifier,
            ],
        );
        let intent = Self {
            intent_id,
            domain_id: domain_id.to_string(),
            guardian_set_id: guardian_set_id.to_string(),
            account_commitment: account_commitment.to_string(),
            recovery_secret_commitment: recovery_secret_commitment.to_string(),
            new_authority_commitment: new_authority_commitment.to_string(),
            privacy_nullifier: privacy_nullifier.to_string(),
            encrypted_recovery_payload_root: encrypted_recovery_payload_root.to_string(),
            fee_sponsor_commitment: fee_sponsor_commitment.to_string(),
            opened_height,
            ready_height: opened_height.saturating_add(execution_delay_blocks),
            expiry_height: opened_height.saturating_add(ttl_blocks),
            status: RecoveryIntentStatus::Open,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.intent_id.trim().is_empty()
            || self.domain_id.trim().is_empty()
            || self.guardian_set_id.trim().is_empty()
        {
            return Err("recovery intent ids cannot be empty".to_string());
        }
        if self.account_commitment.trim().is_empty()
            || self.recovery_secret_commitment.trim().is_empty()
            || self.new_authority_commitment.trim().is_empty()
            || self.privacy_nullifier.trim().is_empty()
            || self.encrypted_recovery_payload_root.trim().is_empty()
            || self.fee_sponsor_commitment.trim().is_empty()
        {
            return Err("recovery intent commitments cannot be empty".to_string());
        }
        if self.ready_height < self.opened_height || self.expiry_height < self.ready_height {
            return Err("recovery intent heights are inconsistent".to_string());
        }
        Ok(())
    }

    pub fn is_open(&self, height: u64) -> bool {
        matches!(
            self.status,
            RecoveryIntentStatus::Open
                | RecoveryIntentStatus::Attested
                | RecoveryIntentStatus::Ready
        ) && height <= self.expiry_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_cross_contract_recovery_intent",
            "intent_id": self.intent_id,
            "domain_id": self.domain_id,
            "guardian_set_id": self.guardian_set_id,
            "account_commitment": self.account_commitment,
            "recovery_secret_commitment": self.recovery_secret_commitment,
            "new_authority_commitment": self.new_authority_commitment,
            "privacy_nullifier": self.privacy_nullifier,
            "encrypted_recovery_payload_root": self.encrypted_recovery_payload_root,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "opened_height": self.opened_height,
            "ready_height": self.ready_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_pq_cross_contract_account_recovery_payload_root("INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianAttestation {
    pub attestation_id: String,
    pub intent_id: String,
    pub guardian_commitment: String,
    pub pq_signature_commitment: String,
    pub eligibility_proof_root: String,
    pub attested_height: u64,
    pub status: GuardianAttestationStatus,
}

impl GuardianAttestation {
    pub fn new(
        intent_id: &str,
        guardian_commitment: &str,
        pq_signature_commitment: &str,
        eligibility_proof_root: &str,
        attested_height: u64,
    ) -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        let attestation_id = private_pq_cross_contract_account_recovery_id(
            "ATTESTATION",
            &[
                intent_id,
                guardian_commitment,
                pq_signature_commitment,
                eligibility_proof_root,
            ],
        );
        let attestation = Self {
            attestation_id,
            intent_id: intent_id.to_string(),
            guardian_commitment: guardian_commitment.to_string(),
            pq_signature_commitment: pq_signature_commitment.to_string(),
            eligibility_proof_root: eligibility_proof_root.to_string(),
            attested_height,
            status: GuardianAttestationStatus::Pending,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.attestation_id.trim().is_empty()
            || self.intent_id.trim().is_empty()
            || self.guardian_commitment.trim().is_empty()
            || self.pq_signature_commitment.trim().is_empty()
            || self.eligibility_proof_root.trim().is_empty()
        {
            return Err("guardian attestation fields cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_cross_contract_guardian_attestation",
            "attestation_id": self.attestation_id,
            "intent_id": self.intent_id,
            "guardian_commitment": self.guardian_commitment,
            "pq_signature_commitment": self.pq_signature_commitment,
            "eligibility_proof_root": self.eligibility_proof_root,
            "attested_height": self.attested_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_pq_cross_contract_account_recovery_payload_root(
            "ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryExecutionReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub execution_root: String,
    pub updated_authority_root: String,
    pub cross_contract_call_root: String,
    pub monero_anchor_commitment: String,
    pub executed_height: u64,
}

impl RecoveryExecutionReceipt {
    pub fn new(
        intent_id: &str,
        execution_root: &str,
        updated_authority_root: &str,
        cross_contract_call_root: &str,
        monero_anchor_commitment: &str,
        executed_height: u64,
    ) -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        let receipt_id = private_pq_cross_contract_account_recovery_id(
            "RECEIPT",
            &[
                intent_id,
                execution_root,
                updated_authority_root,
                cross_contract_call_root,
                monero_anchor_commitment,
            ],
        );
        let receipt = Self {
            receipt_id,
            intent_id: intent_id.to_string(),
            execution_root: execution_root.to_string(),
            updated_authority_root: updated_authority_root.to_string(),
            cross_contract_call_root: cross_contract_call_root.to_string(),
            monero_anchor_commitment: monero_anchor_commitment.to_string(),
            executed_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.receipt_id.trim().is_empty()
            || self.intent_id.trim().is_empty()
            || self.execution_root.trim().is_empty()
            || self.updated_authority_root.trim().is_empty()
            || self.cross_contract_call_root.trim().is_empty()
            || self.monero_anchor_commitment.trim().is_empty()
        {
            return Err("recovery receipt fields cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_cross_contract_recovery_receipt",
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "execution_root": self.execution_root,
            "updated_authority_root": self.updated_authority_root,
            "cross_contract_call_root": self.cross_contract_call_root,
            "monero_anchor_commitment": self.monero_anchor_commitment,
            "executed_height": self.executed_height,
        })
    }

    pub fn root(&self) -> String {
        private_pq_cross_contract_account_recovery_payload_root("RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallenge {
    pub challenge_id: String,
    pub intent_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub status: RecoveryChallengeStatus,
}

impl RecoveryChallenge {
    pub fn new(
        intent_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        opened_height: u64,
        challenge_blocks: u64,
    ) -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        let challenge_id = private_pq_cross_contract_account_recovery_id(
            "CHALLENGE",
            &[intent_id, challenger_commitment, evidence_root],
        );
        let challenge = Self {
            challenge_id,
            intent_id: intent_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_height,
            expiry_height: opened_height.saturating_add(challenge_blocks),
            status: RecoveryChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.challenge_id.trim().is_empty()
            || self.intent_id.trim().is_empty()
            || self.challenger_commitment.trim().is_empty()
            || self.evidence_root.trim().is_empty()
        {
            return Err("recovery challenge fields cannot be empty".to_string());
        }
        if self.expiry_height < self.opened_height {
            return Err("recovery challenge expiry cannot precede open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_cross_contract_recovery_challenge",
            "challenge_id": self.challenge_id,
            "intent_id": self.intent_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_pq_cross_contract_account_recovery_payload_root("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub intent_ttl_blocks: u64,
    pub execution_delay_blocks: u64,
    pub challenge_blocks: u64,
    pub min_quorum_bps: u64,
    pub max_recovery_fee_micro_units: u64,
    pub low_fee_sponsorship_floor_micro_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            intent_ttl_blocks: PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_DEFAULT_INTENT_TTL_BLOCKS,
            execution_delay_blocks:
                PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_DEFAULT_EXECUTION_DELAY_BLOCKS,
            challenge_blocks: PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_DEFAULT_CHALLENGE_BLOCKS,
            min_quorum_bps: 6_700,
            max_recovery_fee_micro_units: 150,
            low_fee_sponsorship_floor_micro_units: 8,
        }
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.intent_ttl_blocks == 0 {
            return Err("recovery intent ttl must be positive".to_string());
        }
        if self.execution_delay_blocks > self.intent_ttl_blocks {
            return Err("recovery execution delay exceeds ttl".to_string());
        }
        if self.challenge_blocks == 0 {
            return Err("recovery challenge blocks must be positive".to_string());
        }
        if self.min_quorum_bps == 0
            || self.min_quorum_bps > PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_BPS
        {
            return Err("recovery quorum bps is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "execution_delay_blocks": self.execution_delay_blocks,
            "challenge_blocks": self.challenge_blocks,
            "min_quorum_bps": self.min_quorum_bps,
            "max_recovery_fee_micro_units": self.max_recovery_fee_micro_units,
            "low_fee_sponsorship_floor_micro_units": self.low_fee_sponsorship_floor_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub domain_root: String,
    pub guardian_set_root: String,
    pub intent_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "domain_root": self.domain_root,
            "guardian_set_root": self.guardian_set_root,
            "intent_root": self.intent_root,
            "attestation_root": self.attestation_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub domain_count: u64,
    pub active_guardian_set_count: u64,
    pub open_intent_count: u64,
    pub ready_intent_count: u64,
    pub executed_intent_count: u64,
    pub accepted_attestation_count: u64,
    pub open_challenge_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "domain_count": self.domain_count,
            "active_guardian_set_count": self.active_guardian_set_count,
            "open_intent_count": self.open_intent_count,
            "ready_intent_count": self.ready_intent_count,
            "executed_intent_count": self.executed_intent_count,
            "accepted_attestation_count": self.accepted_attestation_count,
            "open_challenge_count": self.open_challenge_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub domains: BTreeMap<String, RecoveryDomain>,
    pub guardian_sets: BTreeMap<String, GuardianSet>,
    pub intents: BTreeMap<String, RecoveryIntent>,
    pub attestations: BTreeMap<String, GuardianAttestation>,
    pub receipts: BTreeMap<String, RecoveryExecutionReceipt>,
    pub challenges: BTreeMap<String, RecoveryChallenge>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            domains: BTreeMap::new(),
            guardian_sets: BTreeMap::new(),
            intents: BTreeMap::new(),
            attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> PrivatePqCrossContractAccountRecoveryResult<Self> {
        let mut state = Self::new(Config::devnet())?;
        state.insert_domain(RecoveryDomain::new(
            "domain:private-smart-account",
            RecoveryDomainKind::SmartAccount,
            "contract-root:private-smart-account",
            "policy-root:guardian-quorum:devnet",
            "monero-anchor:recovery:0",
            256,
        )?)?;
        state.insert_domain(RecoveryDomain::new(
            "domain:monero-linked-vault",
            RecoveryDomainKind::MoneroLinkedSpendAuthority,
            "contract-root:monero-linked-vault",
            "policy-root:monero-spend-authority:devnet",
            "monero-anchor:vault:0",
            512,
        )?)?;
        let guardian_set = GuardianSet::new(
            "domain:private-smart-account",
            BTreeSet::from([
                "guardian:pq:0".to_string(),
                "guardian:pq:1".to_string(),
                "guardian:pq:2".to_string(),
            ]),
            2,
            "stake-root:guardians:0",
            0,
        )?;
        let guardian_set_id = guardian_set.guardian_set_id.clone();
        state.insert_guardian_set(guardian_set)?;
        let intent = RecoveryIntent::new(
            "domain:private-smart-account",
            &guardian_set_id,
            "account-commitment:alice:0",
            "recovery-secret:commitment:0",
            "new-authority:pq:alice:1",
            "recovery-nullifier:0",
            "encrypted-recovery-payload:0",
            "fee-sponsor:low-fee:0",
            state.height,
            state.config.execution_delay_blocks,
            state.config.intent_ttl_blocks,
        )?;
        let intent_id = state.submit_intent(intent)?;
        state.record_attestation(
            &intent_id,
            "guardian:pq:0",
            "pq-signature:guardian:0",
            "eligibility-proof:guardian:0",
        )?;
        state.record_attestation(
            &intent_id,
            "guardian:pq:1",
            "pq-signature:guardian:1",
            "eligibility-proof:guardian:1",
        )?;
        state.set_height(state.config.execution_delay_blocks)?;
        state.execute_recovery(
            &intent_id,
            "execution-root:recovery:0",
            "updated-authority-root:0",
            "cross-contract-call-root:0",
            "monero-anchor-commitment:0",
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_domain(
        &mut self,
        domain: RecoveryDomain,
    ) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.domains.len() >= PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_DOMAINS
            && !self.domains.contains_key(&domain.domain_id)
        {
            return Err("recovery domain capacity reached".to_string());
        }
        domain.validate()?;
        self.domains.insert(domain.domain_id.clone(), domain);
        Ok(())
    }

    pub fn insert_guardian_set(
        &mut self,
        guardian_set: GuardianSet,
    ) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if self.guardian_sets.len() >= PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_GUARDIAN_SETS
            && !self
                .guardian_sets
                .contains_key(&guardian_set.guardian_set_id)
        {
            return Err("guardian set capacity reached".to_string());
        }
        guardian_set.validate()?;
        if !self.domains.contains_key(&guardian_set.domain_id) {
            return Err("guardian set domain missing".to_string());
        }
        self.guardian_sets
            .insert(guardian_set.guardian_set_id.clone(), guardian_set);
        Ok(())
    }

    pub fn submit_intent(
        &mut self,
        intent: RecoveryIntent,
    ) -> PrivatePqCrossContractAccountRecoveryResult<String> {
        if self.intents.len() >= PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_INTENTS {
            return Err("recovery intent capacity reached".to_string());
        }
        intent.validate()?;
        if self.consumed_nullifiers.contains(&intent.privacy_nullifier) {
            return Err("recovery intent nullifier already consumed".to_string());
        }
        let domain = self
            .domains
            .get(&intent.domain_id)
            .ok_or_else(|| "recovery intent domain missing".to_string())?;
        if !domain.active {
            return Err("recovery intent domain inactive".to_string());
        }
        let guardian_set = self
            .guardian_sets
            .get(&intent.guardian_set_id)
            .ok_or_else(|| "recovery intent guardian set missing".to_string())?;
        if !guardian_set.active || guardian_set.domain_id != intent.domain_id {
            return Err("recovery intent guardian set invalid".to_string());
        }
        let intent_id = intent.intent_id.clone();
        self.consumed_nullifiers
            .insert(intent.privacy_nullifier.clone());
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn record_attestation(
        &mut self,
        intent_id: &str,
        guardian_commitment: &str,
        pq_signature_commitment: &str,
        eligibility_proof_root: &str,
    ) -> PrivatePqCrossContractAccountRecoveryResult<String> {
        if self.attestations.len() >= PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_ATTESTATIONS {
            return Err("guardian attestation capacity reached".to_string());
        }
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "guardian attestation intent missing".to_string())?;
        if !intent.is_open(self.height) {
            return Err("guardian attestation intent is not open".to_string());
        }
        let guardian_set = self
            .guardian_sets
            .get(&intent.guardian_set_id)
            .ok_or_else(|| "guardian attestation guardian set missing".to_string())?;
        if !guardian_set
            .guardian_commitments
            .contains(guardian_commitment)
        {
            return Err("guardian attestation signer is not in set".to_string());
        }
        let mut attestation = GuardianAttestation::new(
            intent_id,
            guardian_commitment,
            pq_signature_commitment,
            eligibility_proof_root,
            self.height,
        )?;
        attestation.status = GuardianAttestationStatus::Accepted;
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_intent_quorum(intent_id)?;
        Ok(attestation_id)
    }

    pub fn refresh_intent_quorum(
        &mut self,
        intent_id: &str,
    ) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        let (guardian_set_id, ready_height) = {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| "quorum intent missing".to_string())?;
            (intent.guardian_set_id.clone(), intent.ready_height)
        };
        let guardian_set = self
            .guardian_sets
            .get(&guardian_set_id)
            .ok_or_else(|| "quorum guardian set missing".to_string())?;
        let accepted = self
            .attestations
            .values()
            .filter(|attestation| attestation.intent_id == intent_id)
            .filter(|attestation| attestation.status == GuardianAttestationStatus::Accepted)
            .map(|attestation| attestation.guardian_commitment.clone())
            .collect::<BTreeSet<_>>();
        if let Some(intent) = self.intents.get_mut(intent_id) {
            if accepted.len() as u64 >= guardian_set.pq_quorum_threshold {
                intent.status = if self.height >= ready_height {
                    RecoveryIntentStatus::Ready
                } else {
                    RecoveryIntentStatus::Attested
                };
            }
        }
        Ok(())
    }

    pub fn execute_recovery(
        &mut self,
        intent_id: &str,
        execution_root: &str,
        updated_authority_root: &str,
        cross_contract_call_root: &str,
        monero_anchor_commitment: &str,
    ) -> PrivatePqCrossContractAccountRecoveryResult<String> {
        if self.receipts.len() >= PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_RECEIPTS {
            return Err("recovery receipt capacity reached".to_string());
        }
        self.refresh_intent_quorum(intent_id)?;
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| "execute recovery intent missing".to_string())?;
        if intent.status != RecoveryIntentStatus::Ready || self.height < intent.ready_height {
            return Err("recovery intent is not ready".to_string());
        }
        let receipt = RecoveryExecutionReceipt::new(
            intent_id,
            execution_root,
            updated_authority_root,
            cross_contract_call_root,
            monero_anchor_commitment,
            self.height,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        intent.status = RecoveryIntentStatus::Executed;
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn open_challenge(
        &mut self,
        intent_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
    ) -> PrivatePqCrossContractAccountRecoveryResult<String> {
        if self.challenges.len() >= PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_CHALLENGES {
            return Err("recovery challenge capacity reached".to_string());
        }
        if !self.intents.contains_key(intent_id) {
            return Err("recovery challenge intent missing".to_string());
        }
        let challenge = RecoveryChallenge::new(
            intent_id,
            challenger_commitment,
            evidence_root,
            self.height,
            self.config.challenge_blocks,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.status = RecoveryIntentStatus::Challenged;
        }
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn set_height(&mut self, height: u64) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        if height < self.height {
            return Err("recovery height cannot decrease".to_string());
        }
        self.height = height;
        let intent_ids = self.intents.keys().cloned().collect::<Vec<_>>();
        for intent_id in intent_ids {
            self.refresh_intent_quorum(&intent_id)?;
        }
        for intent in self.intents.values_mut() {
            if matches!(
                intent.status,
                RecoveryIntentStatus::Open
                    | RecoveryIntentStatus::Attested
                    | RecoveryIntentStatus::Ready
            ) && height > intent.expiry_height
            {
                intent.status = RecoveryIntentStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status == RecoveryChallengeStatus::Open && height > challenge.expiry_height
            {
                challenge.status = RecoveryChallengeStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        self.set_height(height)
    }

    pub fn validate(&self) -> PrivatePqCrossContractAccountRecoveryResult<()> {
        self.config.validate()?;
        if self.domains.len() > PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_DOMAINS {
            return Err("too many recovery domains".to_string());
        }
        if self.guardian_sets.len() > PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_GUARDIAN_SETS {
            return Err("too many guardian sets".to_string());
        }
        if self.intents.len() > PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_MAX_INTENTS {
            return Err("too many recovery intents".to_string());
        }
        for domain in self.domains.values() {
            domain.validate()?;
        }
        for guardian_set in self.guardian_sets.values() {
            guardian_set.validate()?;
            if !self.domains.contains_key(&guardian_set.domain_id) {
                return Err("guardian set references unknown domain".to_string());
            }
        }
        for intent in self.intents.values() {
            intent.validate()?;
            if !self.domains.contains_key(&intent.domain_id)
                || !self.guardian_sets.contains_key(&intent.guardian_set_id)
            {
                return Err("intent references missing domain or guardian set".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.intents.contains_key(&attestation.intent_id) {
                return Err("attestation references unknown intent".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.intents.contains_key(&receipt.intent_id) {
                return Err("receipt references unknown intent".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.intents.contains_key(&challenge.intent_id) {
                return Err("challenge references unknown intent".to_string());
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            domain_root: private_pq_cross_contract_account_recovery_record_root(
                "DOMAINS",
                self.domains
                    .values()
                    .map(RecoveryDomain::public_record)
                    .collect(),
            ),
            guardian_set_root: private_pq_cross_contract_account_recovery_record_root(
                "GUARDIAN-SETS",
                self.guardian_sets
                    .values()
                    .map(GuardianSet::public_record)
                    .collect(),
            ),
            intent_root: private_pq_cross_contract_account_recovery_record_root(
                "INTENTS",
                self.intents
                    .values()
                    .map(RecoveryIntent::public_record)
                    .collect(),
            ),
            attestation_root: private_pq_cross_contract_account_recovery_record_root(
                "ATTESTATIONS",
                self.attestations
                    .values()
                    .map(GuardianAttestation::public_record)
                    .collect(),
            ),
            receipt_root: private_pq_cross_contract_account_recovery_record_root(
                "RECEIPTS",
                self.receipts
                    .values()
                    .map(RecoveryExecutionReceipt::public_record)
                    .collect(),
            ),
            challenge_root: private_pq_cross_contract_account_recovery_record_root(
                "CHALLENGES",
                self.challenges
                    .values()
                    .map(RecoveryChallenge::public_record)
                    .collect(),
            ),
            nullifier_root: private_pq_cross_contract_account_recovery_string_set_root(
                "NULLIFIERS",
                &self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            domain_count: self.domains.len() as u64,
            active_guardian_set_count: self
                .guardian_sets
                .values()
                .filter(|guardian_set| guardian_set.active)
                .count() as u64,
            open_intent_count: self
                .intents
                .values()
                .filter(|intent| {
                    matches!(
                        intent.status,
                        RecoveryIntentStatus::Open | RecoveryIntentStatus::Attested
                    )
                })
                .count() as u64,
            ready_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status == RecoveryIntentStatus::Ready)
                .count() as u64,
            executed_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status == RecoveryIntentStatus::Executed)
                .count() as u64,
            accepted_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.status == GuardianAttestationStatus::Accepted)
                .count() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == RecoveryChallengeStatus::Open)
                .count() as u64,
        }
    }

    pub fn active_intent_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| intent.is_open(self.height))
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    pub fn ready_intent_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| intent.status == RecoveryIntentStatus::Ready)
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.status == RecoveryChallengeStatus::Open)
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_pq_cross_contract_account_recovery_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_HASH_SUITE,
            "auth_suite": PRIVATE_PQ_CROSS_CONTRACT_ACCOUNT_RECOVERY_AUTH_SUITE,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_intent_ids": self.active_intent_ids(),
            "ready_intent_ids": self.ready_intent_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

pub fn root_from_record(record: &Value) -> String {
    private_pq_cross_contract_account_recovery_payload_root("STATE", record)
}

pub fn private_pq_cross_contract_account_recovery_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        &format!("PRIVATE-PQ-CROSS-CONTRACT-ACCOUNT-RECOVERY-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_pq_cross_contract_account_recovery_record_root(
    domain: &str,
    records: Vec<Value>,
) -> String {
    merkle_root(
        &format!("PRIVATE-PQ-CROSS-CONTRACT-ACCOUNT-RECOVERY-{domain}"),
        &records,
    )
}

pub fn private_pq_cross_contract_account_recovery_string_set_root(
    domain: &str,
    values: &[String],
) -> String {
    merkle_root(
        &format!("PRIVATE-PQ-CROSS-CONTRACT-ACCOUNT-RECOVERY-{domain}"),
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn private_pq_cross_contract_account_recovery_id(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        &format!("PRIVATE-PQ-CROSS-CONTRACT-ACCOUNT-RECOVERY-ID-{domain}"),
        &[HashPart::Json(&json!({ "parts": parts }))],
        32,
    )
}

pub fn devnet() -> PrivatePqCrossContractAccountRecoveryResult<State> {
    State::devnet()
}
