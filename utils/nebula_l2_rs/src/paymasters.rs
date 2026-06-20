use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    contracts::{contract_call_fee, ContractCall},
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    defi::{build_privacy_proof, PrivacyProof},
    fees::FeeMarketResource,
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, DEVNET_PRIVACY_PROOF_BYTES, TARGET_BLOCK_MS,
};

pub const PAYMASTER_DEFAULT_RELAYER_REWARD_UNITS: u64 = 1;
pub const PAYMASTER_REFILL_FAILURE_CHALLENGE_BLOCKS: u64 = 20;
pub const PAYMASTER_MIN_RELAYER_BOND_UNITS: u64 = 1;

pub type PaymasterResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterPolicy {
    pub per_call_cap: u64,
    pub per_caller_cap: u64,
    pub allowed_caller_commitments: Vec<String>,
    pub replenish_threshold: u64,
    pub replenish_target: u64,
    pub relayer_reward_units: u64,
    pub relayer_reward_budget: u64,
}

impl Default for PaymasterPolicy {
    fn default() -> Self {
        Self {
            per_call_cap: 0,
            per_caller_cap: 0,
            allowed_caller_commitments: Vec::new(),
            replenish_threshold: 0,
            replenish_target: 0,
            relayer_reward_units: PAYMASTER_DEFAULT_RELAYER_REWARD_UNITS,
            relayer_reward_budget: 0,
        }
    }
}

impl PaymasterPolicy {
    pub fn normalized(mut self) -> Self {
        self.allowed_caller_commitments.sort();
        self.allowed_caller_commitments.dedup();
        self
    }

    pub fn public_record(&self) -> Value {
        let normalized = self.clone().normalized();
        json!({
            "per_call_cap": normalized.per_call_cap,
            "per_caller_cap": normalized.per_caller_cap,
            "allowed_caller_commitments": normalized.allowed_caller_commitments,
            "replenish_threshold": normalized.replenish_threshold,
            "replenish_target": normalized.replenish_target,
            "relayer_reward_units": normalized.relayer_reward_units,
            "relayer_reward_budget": normalized.relayer_reward_budget,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paymaster {
    pub paymaster_id: String,
    pub contract_id: String,
    pub fee_asset_id: String,
    pub sponsor_label: String,
    pub balance: u64,
    pub spent_amount: u64,
    pub deposit_count: u64,
    pub status: String,
    pub policy: PaymasterPolicy,
    pub spent_by_caller: BTreeMap<String, u64>,
    pub paused_reason_hash: String,
    pub last_governance_action_id: String,
}

impl Paymaster {
    pub fn policy_hash(&self) -> String {
        paymaster_policy_hash(&self.contract_id, &self.fee_asset_id, &self.policy)
    }

    pub fn public_record(&self) -> Value {
        let policy = self.policy.clone().normalized();
        json!({
            "paymaster_id": self.paymaster_id,
            "contract_id": self.contract_id,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_commitment": paymaster_sponsor_commitment(&self.sponsor_label),
            "policy_hash": self.policy_hash(),
            "per_call_cap": policy.per_call_cap,
            "per_caller_cap": policy.per_caller_cap,
            "allowed_caller_commitments": policy.allowed_caller_commitments,
            "balance": self.balance,
            "spent_amount": self.spent_amount,
            "spent_by_caller": self.spent_by_caller,
            "deposit_count": self.deposit_count,
            "status": self.status,
            "replenish_threshold": policy.replenish_threshold,
            "replenish_target": policy.replenish_target,
            "relayer_reward_units": policy.relayer_reward_units,
            "relayer_reward_budget": policy.relayer_reward_budget,
            "paused_reason_hash": self.paused_reason_hash,
            "last_governance_action_id": self.last_governance_action_id,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("paymaster state record object")
            .insert(
                "sponsor_label".to_string(),
                Value::String(self.sponsor_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterDeposit {
    pub paymaster_id: String,
    pub spent_note_id: String,
    pub nullifier: String,
    pub amount: u64,
    pub output_commitments: Vec<String>,
    pub refill_authorization_id: String,
    pub refill_relayer_commitment: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl PaymasterDeposit {
    pub fn terms_hash(&self) -> String {
        domain_hash(
            "PAYMASTER-DEPOSIT-TERMS",
            &[
                HashPart::Str(&self.paymaster_id),
                HashPart::Int(self.amount as i128),
                HashPart::Json(&json!(self.output_commitments)),
                HashPart::Str(&self.refill_authorization_id),
                HashPart::Str(&self.refill_relayer_commitment),
            ],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = json!({
            "kind": "paymaster_deposit",
            "paymaster_id": self.paymaster_id,
            "spent_note_id": self.spent_note_id,
            "nullifier": self.nullifier,
            "amount": self.amount,
            "terms_hash": self.terms_hash(),
            "output_commitments": self.output_commitments,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if !self.refill_authorization_id.is_empty() {
            record
                .as_object_mut()
                .expect("paymaster deposit record object")
                .insert(
                    "refill_authorization_id".to_string(),
                    Value::String(self.refill_authorization_id.clone()),
                );
        }
        if !self.refill_relayer_commitment.is_empty() {
            record
                .as_object_mut()
                .expect("paymaster deposit record object")
                .insert(
                    "refill_relayer_commitment".to_string(),
                    Value::String(self.refill_relayer_commitment.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("paymaster deposit object");
        object.remove("spent_note_id");
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("paymaster deposit state object");
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterSponsoredCall {
    pub sponsorship_id: String,
    pub paymaster_id: String,
    pub call_tx_hash: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub fee_asset_id: String,
    pub sponsored_fee: u64,
    pub balance_before: u64,
    pub balance_after: u64,
    pub spent_by_caller_before: u64,
    pub spent_by_caller_after: u64,
    pub policy_hash: String,
    pub call_public_record_hash: String,
    pub block_height: u64,
}

impl PaymasterSponsoredCall {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "paymaster_id": self.paymaster_id,
            "call_tx_hash": self.call_tx_hash,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "fee_asset_id": self.fee_asset_id,
            "sponsored_fee": self.sponsored_fee,
            "balance_before": self.balance_before,
            "balance_after": self.balance_after,
            "spent_by_caller_before": self.spent_by_caller_before,
            "spent_by_caller_after": self.spent_by_caller_after,
            "policy_hash": self.policy_hash,
            "call_public_record_hash": self.call_public_record_hash,
            "block_height": self.block_height,
        })
    }

    pub fn expected_sponsorship_id(&self) -> String {
        domain_hash(
            "PAYMASTER-SPONSORED-CALL-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.id_payload();
        record
            .as_object_mut()
            .expect("paymaster sponsorship record object")
            .insert(
                "kind".to_string(),
                Value::String("paymaster_sponsored_contract_call".to_string()),
            );
        record
            .as_object_mut()
            .expect("paymaster sponsorship record object")
            .insert(
                "sponsorship_id".to_string(),
                Value::String(self.sponsorship_id.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedPaymasterSponsorship {
    pub sponsorship: PaymasterSponsoredCall,
    pub paymaster_before: Paymaster,
    pub paymaster_after: Paymaster,
    pub fee_resource: FeeMarketResource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterGovernanceAction {
    pub action_id: String,
    pub action_nonce: u64,
    pub paymaster_id: String,
    pub action: String,
    pub sponsor_label: String,
    pub sponsor_commitment: String,
    pub previous_status: String,
    pub new_status: String,
    pub previous_policy_hash: String,
    pub new_policy_hash: String,
    pub reason_hash: String,
    pub policy: PaymasterPolicy,
    pub effective_height: u64,
    pub created_at_ms: u64,
    pub refund_amount: u64,
    pub refund_note_commitment: String,
    pub authorization: Authorization,
}

impl PaymasterGovernanceAction {
    pub fn id_payload(&self) -> Value {
        let policy = self.policy.clone().normalized();
        json!({
            "chain_id": CHAIN_ID,
            "action_nonce": self.action_nonce,
            "paymaster_id": self.paymaster_id,
            "action": self.action,
            "sponsor_commitment": self.sponsor_commitment,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "previous_policy_hash": self.previous_policy_hash,
            "new_policy_hash": self.new_policy_hash,
            "reason_hash": self.reason_hash,
            "per_call_cap": policy.per_call_cap,
            "per_caller_cap": policy.per_caller_cap,
            "allowed_caller_commitments": policy.allowed_caller_commitments,
            "replenish_threshold": policy.replenish_threshold,
            "replenish_target": policy.replenish_target,
            "relayer_reward_units": policy.relayer_reward_units,
            "relayer_reward_budget": policy.relayer_reward_budget,
            "refund_amount": self.refund_amount,
            "refund_note_commitment": self.refund_note_commitment,
            "effective_height": self.effective_height,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn expected_action_id(&self) -> String {
        domain_hash(
            "PAYMASTER-GOVERNANCE-ACTION-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.id_payload();
        let object = record
            .as_object_mut()
            .expect("paymaster governance record object");
        object.insert(
            "kind".to_string(),
            Value::String("paymaster_governance_action".to_string()),
        );
        object.insert(
            "action_id".to_string(),
            Value::String(self.action_id.clone()),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("paymaster governance public object");
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("paymaster governance state object")
            .insert(
                "sponsor_label".to_string(),
                Value::String(self.sponsor_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterRelayerBond {
    pub bond_id: String,
    pub bond_nonce: u64,
    pub relayer_label: String,
    pub relayer_commitment: String,
    pub asset_id: String,
    pub note_commitment: String,
    pub nullifier: String,
    pub amount: u64,
    pub active_amount: u64,
    pub slashed_amount: u64,
    pub withdrawn_amount: u64,
    pub slash_count: u64,
    pub bonded_at_height: u64,
    pub bonded_at_ms: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl PaymasterRelayerBond {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "bond_nonce": self.bond_nonce,
            "relayer_commitment": self.relayer_commitment,
            "asset_id": self.asset_id,
            "note_commitment": self.note_commitment,
            "nullifier": self.nullifier,
            "amount": self.amount,
            "change_note_commitment": "",
            "bonded_at_height": self.bonded_at_height,
            "bonded_at_ms": self.bonded_at_ms,
        })
    }

    pub fn expected_bond_id(&self) -> String {
        domain_hash(
            "PAYMASTER-RELAYER-BOND-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.id_payload();
        let object = record
            .as_object_mut()
            .expect("paymaster bond record object");
        object.insert(
            "kind".to_string(),
            Value::String("paymaster_relayer_bond".to_string()),
        );
        object.insert("bond_id".to_string(), Value::String(self.bond_id.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("paymaster bond object");
        object.insert("active_amount".to_string(), json!(self.active_amount));
        object.insert("slashed_amount".to_string(), json!(self.slashed_amount));
        object.insert("withdrawn_amount".to_string(), json!(self.withdrawn_amount));
        object.insert("slash_count".to_string(), json!(self.slash_count));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("paymaster bond state object")
            .insert(
                "relayer_label".to_string(),
                Value::String(self.relayer_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterRelayerRewardReceipt {
    pub reward_id: String,
    pub paymaster_id: String,
    pub relayer_label: String,
    pub relayer_commitment: String,
    pub fee_asset_id: String,
    pub refill_amount: u64,
    pub reward_units: u64,
    pub deposit_tx_hash: String,
    pub rewarded_at_height: u64,
    pub rewarded_at_ms: u64,
    pub budget_units_before: u64,
    pub budget_units_after: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl PaymasterRelayerRewardReceipt {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "authorization_id": "",
            "paymaster_id": self.paymaster_id,
            "relayer_commitment": self.relayer_commitment,
            "fee_asset_id": self.fee_asset_id,
            "refill_amount": self.refill_amount,
            "reward_units": self.reward_units,
            "deposit_tx_hash": self.deposit_tx_hash,
            "rewarded_at_height": self.rewarded_at_height,
            "rewarded_at_ms": self.rewarded_at_ms,
            "budget_units_before": self.budget_units_before,
            "budget_units_after": self.budget_units_after,
            "reward_budget": self.budget_units_after,
        })
    }

    pub fn expected_reward_id(&self) -> String {
        domain_hash(
            "PAYMASTER-RELAYER-REWARD-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.id_payload();
        let object = record
            .as_object_mut()
            .expect("paymaster reward record object");
        object.insert(
            "kind".to_string(),
            Value::String("paymaster_relayer_reward_receipt".to_string()),
        );
        object.insert(
            "reward_id".to_string(),
            Value::String(self.reward_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("paymaster reward object");
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("paymaster reward state object")
            .insert(
                "relayer_label".to_string(),
                Value::String(self.relayer_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterRelayerSlashingHook {
    pub hook_id: String,
    pub paymaster_id: String,
    pub relayer_label: String,
    pub relayer_commitment: String,
    pub reporter_label: String,
    pub reporter_commitment: String,
    pub reason_code: String,
    pub evidence_hash: String,
    pub penalty_units: u64,
    pub challenge_deadline_height: u64,
    pub slashed_at_height: u64,
    pub slashed_at_ms: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl PaymasterRelayerSlashingHook {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "receipt_id": "",
            "authorization_id": "",
            "paymaster_id": self.paymaster_id,
            "relayer_commitment": self.relayer_commitment,
            "reporter_commitment": self.reporter_commitment,
            "reason_code": self.reason_code,
            "evidence_hash": self.evidence_hash,
            "penalty_units": self.penalty_units,
            "challenge_deadline_height": self.challenge_deadline_height,
            "slashed_at_height": self.slashed_at_height,
            "slashed_at_ms": self.slashed_at_ms,
        })
    }

    pub fn expected_hook_id(&self) -> String {
        domain_hash(
            "PAYMASTER-RELAYER-SLASHING-HOOK-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.id_payload();
        let object = record
            .as_object_mut()
            .expect("paymaster slashing hook record object");
        object.insert(
            "kind".to_string(),
            Value::String("paymaster_relayer_slashing_hook".to_string()),
        );
        object.insert("hook_id".to_string(), Value::String(self.hook_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("paymaster slashing hook object");
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("paymaster slashing hook state object");
        object.insert(
            "relayer_label".to_string(),
            Value::String(self.relayer_label.clone()),
        );
        object.insert(
            "reporter_label".to_string(),
            Value::String(self.reporter_label.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterRelayerSlashSettlement {
    pub settlement_id: String,
    pub hook_id: String,
    pub paymaster_id: String,
    pub relayer_commitment: String,
    pub reporter_commitment: String,
    pub asset_id: String,
    pub penalty_units: u64,
    pub slashed_amount: u64,
    pub remaining_penalty_units: u64,
    pub bond_id: String,
    pub bond_active_after: u64,
    pub settled_at_height: u64,
    pub settled_at_ms: u64,
    pub status: String,
}

impl PaymasterRelayerSlashSettlement {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "hook_id": self.hook_id,
            "receipt_id": "",
            "authorization_id": "",
            "paymaster_id": self.paymaster_id,
            "relayer_commitment": self.relayer_commitment,
            "reporter_commitment": self.reporter_commitment,
            "asset_id": self.asset_id,
            "penalty_units": self.penalty_units,
            "slashed_amount": self.slashed_amount,
            "remaining_penalty_units": self.remaining_penalty_units,
            "bond_deltas": [{
                "bond_id": self.bond_id,
                "slashed_amount": self.slashed_amount,
                "bond_active_after": self.bond_active_after,
            }],
            "settled_at_height": self.settled_at_height,
            "settled_at_ms": self.settled_at_ms,
            "status": self.status,
        })
    }

    pub fn expected_settlement_id(&self) -> String {
        domain_hash(
            "PAYMASTER-RELAYER-SLASH-SETTLEMENT-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.id_payload();
        let object = record
            .as_object_mut()
            .expect("paymaster slash settlement object");
        object.insert(
            "kind".to_string(),
            Value::String("paymaster_relayer_slash_settlement".to_string()),
        );
        object.insert(
            "settlement_id".to_string(),
            Value::String(self.settlement_id.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterState {
    pub paymasters: BTreeMap<String, Paymaster>,
    pub deposits: BTreeMap<String, PaymasterDeposit>,
    pub sponsorships: BTreeMap<String, PaymasterSponsoredCall>,
    pub governance_actions: BTreeMap<String, PaymasterGovernanceAction>,
    pub relayer_bonds: BTreeMap<String, PaymasterRelayerBond>,
    pub relayer_rewards: BTreeMap<String, PaymasterRelayerRewardReceipt>,
    pub slashing_hooks: BTreeMap<String, PaymasterRelayerSlashingHook>,
    pub slash_settlements: BTreeMap<String, PaymasterRelayerSlashSettlement>,
    pub height: u64,
}

impl PaymasterState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_paymaster(
        &mut self,
        contract_id: &str,
        fee_asset_id: &str,
        sponsor_label: &str,
        policy: PaymasterPolicy,
    ) -> PaymasterResult<Paymaster> {
        if contract_id.is_empty() {
            return Err("paymaster contract_id is required".to_string());
        }
        if fee_asset_id.is_empty() {
            return Err("paymaster fee_asset_id is required".to_string());
        }
        if sponsor_label.is_empty() {
            return Err("paymaster sponsor_label is required".to_string());
        }
        let policy = policy.normalized();
        let policy_hash = paymaster_policy_hash(contract_id, fee_asset_id, &policy);
        let paymaster_id = domain_hash(
            "PAYMASTER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(contract_id),
                HashPart::Str(fee_asset_id),
                HashPart::Str(&paymaster_sponsor_commitment(sponsor_label)),
                HashPart::Str(&policy_hash),
                HashPart::Int(self.paymasters.len() as i128),
            ],
            32,
        );
        let paymaster = Paymaster {
            paymaster_id: paymaster_id.clone(),
            contract_id: contract_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            sponsor_label: sponsor_label.to_string(),
            balance: 0,
            spent_amount: 0,
            deposit_count: 0,
            status: "active".to_string(),
            policy,
            spent_by_caller: BTreeMap::new(),
            paused_reason_hash: String::new(),
            last_governance_action_id: String::new(),
        };
        self.paymasters.insert(paymaster_id, paymaster.clone());
        Ok(paymaster)
    }

    pub fn submit_deposit(
        &mut self,
        paymaster_id: &str,
        spent_note_id: &str,
        amount: u64,
        signer_label: &str,
    ) -> PaymasterResult<PaymasterDeposit> {
        if amount == 0 {
            return Err("paymaster deposit amount must be positive".to_string());
        }
        let paymaster = self.require_paymaster(paymaster_id)?.clone();
        if paymaster.sponsor_label != signer_label {
            return Err("paymaster deposit signer must be sponsor".to_string());
        }
        let nonce = self.deposits.len() as u64;
        let output_commitment = domain_hash(
            "PAYMASTER-DEPOSIT-OUTPUT",
            &[
                HashPart::Str(paymaster_id),
                HashPart::Str(spent_note_id),
                HashPart::Int(amount as i128),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let nullifier = domain_hash(
            "PAYMASTER-DEPOSIT-NULLIFIER",
            &[
                HashPart::Str(paymaster_id),
                HashPart::Str(spent_note_id),
                HashPart::Int(amount as i128),
            ],
            32,
        );
        let proof_system = "devnet-mock-private-paymaster-deposit-proof".to_string();
        let public_inputs = json!({
            "kind": "paymaster_deposit",
            "paymaster_id": paymaster_id,
            "nullifier": nullifier,
            "amount": amount,
            "output_commitments": [output_commitment],
        });
        let private_witnesses = json!({
            "spent_note_id": spent_note_id,
            "signer_label": signer_label,
        });
        let privacy_proof = build_privacy_proof(&proof_system, &public_inputs, &private_witnesses);
        let mut deposit = PaymasterDeposit {
            paymaster_id: paymaster_id.to_string(),
            spent_note_id: spent_note_id.to_string(),
            nullifier,
            amount,
            output_commitments: vec![output_commitment],
            refill_authorization_id: String::new(),
            refill_relayer_commitment: String::new(),
            signer_label: signer_label.to_string(),
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        deposit.authorization = sign_authorization(
            signer_label,
            "paymaster_deposit",
            &deposit.unsigned_record(),
        );
        if !verify_authorization(
            signer_label,
            "paymaster_deposit",
            &deposit.unsigned_record(),
            &deposit.authorization,
        ) {
            return Err("invalid paymaster deposit authorization".to_string());
        }
        self.paymasters
            .get_mut(paymaster_id)
            .expect("paymaster exists")
            .balance += amount;
        self.paymasters
            .get_mut(paymaster_id)
            .expect("paymaster exists")
            .deposit_count += 1;
        self.deposits
            .insert(deposit.nullifier.clone(), deposit.clone());
        Ok(deposit)
    }

    pub fn apply_sponsored_call(
        &mut self,
        call: &ContractCall,
    ) -> PaymasterResult<AppliedPaymasterSponsorship> {
        if call.paymaster_id.is_empty() {
            return Err("contract call has no paymaster".to_string());
        }
        if !verify_authorization(
            &call.signer_label,
            "contract_call",
            &call.unsigned_record(),
            &call.authorization,
        ) {
            return Err("invalid sponsored call authorization".to_string());
        }
        let paymaster_before = self.require_paymaster(&call.paymaster_id)?.clone();
        if paymaster_before.status != "active" {
            return Err("paymaster is not active".to_string());
        }
        if call.contract_id != paymaster_before.contract_id {
            return Err("paymaster contract mismatch".to_string());
        }
        if call.fee_asset_id != paymaster_before.fee_asset_id {
            return Err("paymaster fee asset mismatch".to_string());
        }
        if call.fee == 0 {
            return Err("sponsored call fee must be positive".to_string());
        }
        let expected_fee = contract_call_fee(call.fuel_used)?;
        if call.fee != expected_fee {
            return Err("sponsored call fee mismatch".to_string());
        }
        if paymaster_before.policy.per_call_cap > 0
            && call.fee > paymaster_before.policy.per_call_cap
        {
            return Err("paymaster per-call cap exceeded".to_string());
        }
        let caller_commitment = paymaster_caller_commitment(&call.signer_label);
        if !paymaster_before
            .policy
            .allowed_caller_commitments
            .is_empty()
            && !paymaster_before
                .policy
                .allowed_caller_commitments
                .contains(&caller_commitment)
        {
            return Err("caller is not allowed by paymaster policy".to_string());
        }
        let spent_by_caller_before = *paymaster_before
            .spent_by_caller
            .get(&caller_commitment)
            .unwrap_or(&0);
        let spent_by_caller_after = spent_by_caller_before + call.fee;
        if paymaster_before.policy.per_caller_cap > 0
            && spent_by_caller_after > paymaster_before.policy.per_caller_cap
        {
            return Err("paymaster per-caller cap exceeded".to_string());
        }
        if paymaster_before.balance < call.fee {
            return Err("paymaster balance is insufficient".to_string());
        }
        let call_public_record_hash = domain_hash(
            "PAYMASTER-CALL-PUBLIC-RECORD",
            &[HashPart::Json(&call.public_record())],
            32,
        );
        let call_tx_hash = domain_hash(
            "CONTRACT-CALL-TX",
            &[HashPart::Json(&call.public_record())],
            32,
        );
        let mut sponsorship = PaymasterSponsoredCall {
            sponsorship_id: String::new(),
            paymaster_id: call.paymaster_id.clone(),
            call_tx_hash,
            contract_id: call.contract_id.clone(),
            caller_commitment: caller_commitment.clone(),
            fee_asset_id: call.fee_asset_id.clone(),
            sponsored_fee: call.fee,
            balance_before: paymaster_before.balance,
            balance_after: paymaster_before.balance - call.fee,
            spent_by_caller_before,
            spent_by_caller_after,
            policy_hash: paymaster_before.policy_hash(),
            call_public_record_hash,
            block_height: self.height,
        };
        sponsorship.sponsorship_id = sponsorship.expected_sponsorship_id();
        let paymaster = self
            .paymasters
            .get_mut(&call.paymaster_id)
            .expect("paymaster exists");
        paymaster.balance -= call.fee;
        paymaster.spent_amount += call.fee;
        paymaster
            .spent_by_caller
            .insert(caller_commitment, spent_by_caller_after);
        let paymaster_after = paymaster.clone();
        let fee_resource = fee_market_resource_for_paymaster_sponsorship(call, &sponsorship);
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(AppliedPaymasterSponsorship {
            sponsorship,
            paymaster_before,
            paymaster_after,
            fee_resource,
        })
    }

    pub fn pause_paymaster(
        &mut self,
        paymaster_id: &str,
        sponsor_label: &str,
        reason: &str,
    ) -> PaymasterResult<PaymasterGovernanceAction> {
        let reason_hash = domain_hash("PAYMASTER-PAUSE-REASON", &[HashPart::Str(reason)], 32);
        self.apply_governance_action(
            paymaster_id,
            sponsor_label,
            "pause",
            "paused",
            None,
            reason_hash,
        )
    }

    pub fn resume_paymaster(
        &mut self,
        paymaster_id: &str,
        sponsor_label: &str,
    ) -> PaymasterResult<PaymasterGovernanceAction> {
        self.apply_governance_action(
            paymaster_id,
            sponsor_label,
            "resume",
            "active",
            None,
            String::new(),
        )
    }

    pub fn update_policy(
        &mut self,
        paymaster_id: &str,
        sponsor_label: &str,
        policy: PaymasterPolicy,
    ) -> PaymasterResult<PaymasterGovernanceAction> {
        self.apply_governance_action(
            paymaster_id,
            sponsor_label,
            "update_policy",
            "active",
            Some(policy),
            String::new(),
        )
    }

    pub fn bond_relayer(
        &mut self,
        relayer_label: &str,
        asset_id: &str,
        note_commitment: &str,
        amount: u64,
    ) -> PaymasterResult<PaymasterRelayerBond> {
        if amount < PAYMASTER_MIN_RELAYER_BOND_UNITS {
            return Err("paymaster relayer bond amount is too small".to_string());
        }
        if asset_id.is_empty() || note_commitment.is_empty() {
            return Err("paymaster relayer bond asset and note are required".to_string());
        }
        let bond_nonce = self.relayer_bonds.len() as u64;
        let relayer_commitment = paymaster_relayer_commitment(relayer_label);
        let nullifier = domain_hash(
            "PAYMASTER-RELAYER-BOND-NULLIFIER",
            &[
                HashPart::Str(&relayer_commitment),
                HashPart::Str(asset_id),
                HashPart::Str(note_commitment),
                HashPart::Int(amount as i128),
            ],
            32,
        );
        let mut bond = PaymasterRelayerBond {
            bond_id: String::new(),
            bond_nonce,
            relayer_label: relayer_label.to_string(),
            relayer_commitment,
            asset_id: asset_id.to_string(),
            note_commitment: note_commitment.to_string(),
            nullifier,
            amount,
            active_amount: amount,
            slashed_amount: 0,
            withdrawn_amount: 0,
            slash_count: 0,
            bonded_at_height: self.height,
            bonded_at_ms: self.height * TARGET_BLOCK_MS,
            status: "active".to_string(),
            authorization: empty_authorization(),
        };
        bond.bond_id = bond.expected_bond_id();
        bond.authorization = sign_authorization(
            relayer_label,
            "paymaster_relayer_bond",
            &bond.unsigned_record(),
        );
        if !verify_authorization(
            relayer_label,
            "paymaster_relayer_bond",
            &bond.unsigned_record(),
            &bond.authorization,
        ) {
            return Err("invalid paymaster relayer bond authorization".to_string());
        }
        self.relayer_bonds
            .insert(bond.bond_id.clone(), bond.clone());
        Ok(bond)
    }

    pub fn record_relayer_reward(
        &mut self,
        paymaster_id: &str,
        relayer_label: &str,
        refill_amount: u64,
        deposit_tx_hash: &str,
    ) -> PaymasterResult<PaymasterRelayerRewardReceipt> {
        let paymaster = self.require_paymaster(paymaster_id)?.clone();
        let reward_units = paymaster.policy.relayer_reward_units;
        if reward_units == 0 {
            return Err("paymaster relayer rewards are disabled".to_string());
        }
        if paymaster.policy.relayer_reward_budget < reward_units {
            return Err("paymaster relayer reward budget is insufficient".to_string());
        }
        let budget_units_before = paymaster.policy.relayer_reward_budget;
        let budget_units_after = budget_units_before - reward_units;
        let mut reward = PaymasterRelayerRewardReceipt {
            reward_id: String::new(),
            paymaster_id: paymaster_id.to_string(),
            relayer_label: relayer_label.to_string(),
            relayer_commitment: paymaster_relayer_commitment(relayer_label),
            fee_asset_id: paymaster.fee_asset_id.clone(),
            refill_amount,
            reward_units,
            deposit_tx_hash: deposit_tx_hash.to_string(),
            rewarded_at_height: self.height,
            rewarded_at_ms: self.height * TARGET_BLOCK_MS,
            budget_units_before,
            budget_units_after,
            status: "earned".to_string(),
            authorization: empty_authorization(),
        };
        reward.reward_id = reward.expected_reward_id();
        reward.authorization = sign_authorization(
            &paymaster.sponsor_label,
            "paymaster_relayer_reward",
            &reward.unsigned_record(),
        );
        if !verify_authorization(
            &paymaster.sponsor_label,
            "paymaster_relayer_reward",
            &reward.unsigned_record(),
            &reward.authorization,
        ) {
            return Err("invalid paymaster relayer reward authorization".to_string());
        }
        self.paymasters
            .get_mut(paymaster_id)
            .expect("paymaster exists")
            .policy
            .relayer_reward_budget = budget_units_after;
        self.relayer_rewards
            .insert(reward.reward_id.clone(), reward.clone());
        Ok(reward)
    }

    pub fn publish_slashing_hook(
        &mut self,
        paymaster_id: &str,
        relayer_label: &str,
        reporter_label: &str,
        reason_code: &str,
        evidence: &Value,
    ) -> PaymasterResult<PaymasterRelayerSlashingHook> {
        let paymaster = self.require_paymaster(paymaster_id)?;
        let penalty_units = std::cmp::max(1, paymaster.policy.relayer_reward_units);
        let evidence_hash = domain_hash(
            "PAYMASTER-RELAYER-SLASHING-EVIDENCE",
            &[HashPart::Json(evidence)],
            32,
        );
        let mut hook = PaymasterRelayerSlashingHook {
            hook_id: String::new(),
            paymaster_id: paymaster_id.to_string(),
            relayer_label: relayer_label.to_string(),
            relayer_commitment: paymaster_relayer_commitment(relayer_label),
            reporter_label: reporter_label.to_string(),
            reporter_commitment: paymaster_reporter_commitment(reporter_label),
            reason_code: reason_code.to_string(),
            evidence_hash,
            penalty_units,
            challenge_deadline_height: self.height + PAYMASTER_REFILL_FAILURE_CHALLENGE_BLOCKS,
            slashed_at_height: self.height,
            slashed_at_ms: self.height * TARGET_BLOCK_MS,
            status: "slashable".to_string(),
            authorization: empty_authorization(),
        };
        hook.hook_id = hook.expected_hook_id();
        hook.authorization = sign_authorization(
            reporter_label,
            "paymaster_relayer_slashing_hook",
            &hook.unsigned_record(),
        );
        if !verify_authorization(
            reporter_label,
            "paymaster_relayer_slashing_hook",
            &hook.unsigned_record(),
            &hook.authorization,
        ) {
            return Err("invalid paymaster slashing hook authorization".to_string());
        }
        self.slashing_hooks
            .insert(hook.hook_id.clone(), hook.clone());
        Ok(hook)
    }

    pub fn settle_slashing_hook(
        &mut self,
        hook_id: &str,
    ) -> PaymasterResult<PaymasterRelayerSlashSettlement> {
        let hook = self
            .slashing_hooks
            .get(hook_id)
            .ok_or_else(|| "unknown paymaster slashing hook".to_string())?
            .clone();
        if hook.status != "slashable" {
            return Err("paymaster slashing hook is not slashable".to_string());
        }
        let bond_id = self
            .relayer_bonds
            .values()
            .find(|bond| {
                bond.relayer_commitment == hook.relayer_commitment
                    && bond.status == "active"
                    && bond.active_amount > 0
            })
            .map(|bond| bond.bond_id.clone())
            .ok_or_else(|| "no active relayer bond for slashing hook".to_string())?;
        let bond = self.relayer_bonds.get_mut(&bond_id).expect("bond exists");
        let slashed_amount = std::cmp::min(hook.penalty_units, bond.active_amount);
        bond.active_amount -= slashed_amount;
        bond.slashed_amount += slashed_amount;
        bond.slash_count += 1;
        if bond.active_amount == 0 {
            bond.status = "slashed".to_string();
        }
        let remaining_penalty_units = hook.penalty_units - slashed_amount;
        let mut settlement = PaymasterRelayerSlashSettlement {
            settlement_id: String::new(),
            hook_id: hook.hook_id.clone(),
            paymaster_id: hook.paymaster_id.clone(),
            relayer_commitment: hook.relayer_commitment.clone(),
            reporter_commitment: hook.reporter_commitment.clone(),
            asset_id: bond.asset_id.clone(),
            penalty_units: hook.penalty_units,
            slashed_amount,
            remaining_penalty_units,
            bond_id,
            bond_active_after: bond.active_amount,
            settled_at_height: self.height,
            settled_at_ms: self.height * TARGET_BLOCK_MS,
            status: if remaining_penalty_units == 0 {
                "settled".to_string()
            } else {
                "partially_settled".to_string()
            },
        };
        settlement.settlement_id = settlement.expected_settlement_id();
        self.slashing_hooks
            .get_mut(hook_id)
            .expect("hook exists")
            .status = "settled".to_string();
        self.slash_settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        Ok(settlement)
    }

    pub fn paymaster_root(&self) -> String {
        let leaves = self
            .paymasters
            .values()
            .map(Paymaster::public_record)
            .collect::<Vec<_>>();
        merkle_root("PAYMASTER", &leaves)
    }

    pub fn deposit_root(&self) -> String {
        let leaves = self
            .deposits
            .values()
            .map(PaymasterDeposit::public_record)
            .collect::<Vec<_>>();
        merkle_root("PAYMASTER-DEPOSIT", &leaves)
    }

    pub fn sponsorship_root(&self) -> String {
        let leaves = self
            .sponsorships
            .values()
            .map(PaymasterSponsoredCall::public_record)
            .collect::<Vec<_>>();
        merkle_root("PAYMASTER-SPONSORED-CALL", &leaves)
    }

    pub fn relayer_root(&self) -> String {
        let bond_leaves = self
            .relayer_bonds
            .values()
            .map(PaymasterRelayerBond::public_record)
            .collect::<Vec<_>>();
        let reward_leaves = self
            .relayer_rewards
            .values()
            .map(PaymasterRelayerRewardReceipt::public_record)
            .collect::<Vec<_>>();
        let hook_leaves = self
            .slashing_hooks
            .values()
            .map(PaymasterRelayerSlashingHook::public_record)
            .collect::<Vec<_>>();
        let settlement_leaves = self
            .slash_settlements
            .values()
            .map(PaymasterRelayerSlashSettlement::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "PAYMASTER-RELAYER",
            &[json!({
                "bond_root": merkle_root("PAYMASTER-RELAYER-BOND", &bond_leaves),
                "reward_root": merkle_root("PAYMASTER-RELAYER-REWARD", &reward_leaves),
                "slashing_hook_root": merkle_root("PAYMASTER-RELAYER-SLASHING-HOOK", &hook_leaves),
                "slash_settlement_root": merkle_root("PAYMASTER-RELAYER-SLASH-SETTLEMENT", &settlement_leaves),
            })],
        )
    }

    pub fn state_root(&self) -> String {
        merkle_root(
            "PAYMASTER-STATE",
            &[json!({
                "paymaster_count": self.paymasters.len(),
                "paymaster_root": self.paymaster_root(),
                "deposit_count": self.deposits.len(),
                "deposit_root": self.deposit_root(),
                "sponsorship_count": self.sponsorships.len(),
                "sponsorship_root": self.sponsorship_root(),
                "governance_count": self.governance_actions.len(),
                "governance_root": self.governance_root(),
                "relayer_root": self.relayer_root(),
            })],
        )
    }

    pub fn governance_root(&self) -> String {
        let leaves = self
            .governance_actions
            .values()
            .map(PaymasterGovernanceAction::public_record)
            .collect::<Vec<_>>();
        merkle_root("PAYMASTER-GOVERNANCE-ACTION", &leaves)
    }

    fn require_paymaster(&self, paymaster_id: &str) -> PaymasterResult<&Paymaster> {
        self.paymasters
            .get(paymaster_id)
            .ok_or_else(|| "unknown paymaster".to_string())
    }

    fn apply_governance_action(
        &mut self,
        paymaster_id: &str,
        sponsor_label: &str,
        action: &str,
        new_status: &str,
        new_policy: Option<PaymasterPolicy>,
        reason_hash: String,
    ) -> PaymasterResult<PaymasterGovernanceAction> {
        let paymaster = self.require_paymaster(paymaster_id)?.clone();
        if paymaster.sponsor_label != sponsor_label {
            return Err("paymaster governance signer must be sponsor".to_string());
        }
        let policy = new_policy
            .unwrap_or_else(|| paymaster.policy.clone())
            .normalized();
        let new_policy_hash =
            paymaster_policy_hash(&paymaster.contract_id, &paymaster.fee_asset_id, &policy);
        let mut governance = PaymasterGovernanceAction {
            action_id: String::new(),
            action_nonce: self.governance_actions.len() as u64,
            paymaster_id: paymaster_id.to_string(),
            action: action.to_string(),
            sponsor_label: sponsor_label.to_string(),
            sponsor_commitment: paymaster_sponsor_commitment(sponsor_label),
            previous_status: paymaster.status.clone(),
            new_status: new_status.to_string(),
            previous_policy_hash: paymaster.policy_hash(),
            new_policy_hash,
            reason_hash,
            policy: policy.clone(),
            effective_height: self.height,
            created_at_ms: self.height * TARGET_BLOCK_MS,
            refund_amount: 0,
            refund_note_commitment: String::new(),
            authorization: empty_authorization(),
        };
        governance.action_id = governance.expected_action_id();
        governance.authorization = sign_authorization(
            sponsor_label,
            "paymaster_governance_action",
            &governance.unsigned_record(),
        );
        if !verify_authorization(
            sponsor_label,
            "paymaster_governance_action",
            &governance.unsigned_record(),
            &governance.authorization,
        ) {
            return Err("invalid paymaster governance authorization".to_string());
        }
        let paymaster = self
            .paymasters
            .get_mut(paymaster_id)
            .expect("paymaster exists");
        paymaster.status = new_status.to_string();
        paymaster.policy = policy;
        paymaster.paused_reason_hash = governance.reason_hash.clone();
        paymaster.last_governance_action_id = governance.action_id.clone();
        self.governance_actions
            .insert(governance.action_id.clone(), governance.clone());
        Ok(governance)
    }
}

pub fn paymaster_policy_hash(
    contract_id: &str,
    fee_asset_id: &str,
    policy: &PaymasterPolicy,
) -> String {
    domain_hash(
        "PAYMASTER-POLICY",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(fee_asset_id),
            HashPart::Json(&policy.clone().normalized().public_record()),
        ],
        32,
    )
}

pub fn paymaster_sponsor_commitment(sponsor_label: &str) -> String {
    domain_hash("PAYMASTER-SPONSOR", &[HashPart::Str(sponsor_label)], 32)
}

pub fn paymaster_caller_commitment(caller_label: &str) -> String {
    domain_hash("PAYMASTER-CALLER", &[HashPart::Str(caller_label)], 32)
}

pub fn paymaster_relayer_commitment(relayer_label: &str) -> String {
    domain_hash("PAYMASTER-RELAYER", &[HashPart::Str(relayer_label)], 32)
}

pub fn paymaster_reporter_commitment(reporter_label: &str) -> String {
    domain_hash(
        "PAYMASTER-RELAYER-REWARD-QUOTE-REPORTER",
        &[HashPart::Str(reporter_label)],
        32,
    )
}

pub fn fee_market_resource_for_paymaster_sponsorship(
    call: &ContractCall,
    sponsorship: &PaymasterSponsoredCall,
) -> FeeMarketResource {
    let proof_count = u64::from(call.privacy_proof.is_some());
    FeeMarketResource {
        public_record: json!({
            "kind": "paymaster_sponsored_contract_call",
            "contract_call": call.public_record(),
            "sponsorship": sponsorship.public_record(),
        }),
        execution_fuel: call.fuel_used,
        privacy_proof_count: proof_count,
        contract_call_count: 1,
        observed_fee_units: sponsorship.sponsored_fee,
        estimated_proof_bytes: proof_count * DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids: vec![sponsorship.fee_asset_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "contract_call".to_string()),
            (
                "operation".to_string(),
                "paymaster_sponsored_contract_call".to_string(),
            ),
            ("contract".to_string(), sponsorship.contract_id.clone()),
            ("paymaster".to_string(), sponsorship.paymaster_id.clone()),
            ("asset".to_string(), sponsorship.fee_asset_id.clone()),
        ],
    }
}

fn empty_authorization() -> Authorization {
    Authorization {
        signer_label: String::new(),
        auth_scheme: String::new(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::{ContractCallRequest, ContractState},
        fees::execution_profile_from_resources,
    };

    #[test]
    fn paymaster_deposits_and_sponsors_contract_call_without_leaking_labels() {
        let mut contracts = ContractState::new();
        let contract = contracts
            .deploy_counter_contract("alice-view-key", 100, false)
            .unwrap();
        let bob_commitment = paymaster_caller_commitment("bob-view-key");
        let mut paymasters = PaymasterState::new();
        let paymaster = paymasters
            .create_paymaster(
                &contract.contract_id,
                "wxmr-rust",
                "alice-view-key",
                PaymasterPolicy {
                    per_call_cap: 1,
                    per_caller_cap: 2,
                    allowed_caller_commitments: vec![bob_commitment.clone()],
                    replenish_threshold: 1,
                    replenish_target: 5,
                    relayer_reward_units: 1,
                    relayer_reward_budget: 2,
                },
            )
            .unwrap();
        let deposit = paymasters
            .submit_deposit(
                &paymaster.paymaster_id,
                "alice-fee-note-1",
                3,
                "alice-view-key",
            )
            .unwrap();
        assert_eq!(paymasters.paymasters[&paymaster.paymaster_id].balance, 3);
        assert!(!deposit
            .public_record()
            .to_string()
            .contains("alice-fee-note-1"));
        assert!(deposit
            .state_record()
            .to_string()
            .contains("alice-fee-note-1"));

        let applied = contracts
            .execute_contract_call(
                ContractCallRequest::new(
                    &contract.contract_id,
                    "increment",
                    json!({"amount": 7}),
                    "bob-view-key",
                    20,
                )
                .fee_asset("wxmr-rust", Some(1))
                .paymaster(&paymaster.paymaster_id),
            )
            .unwrap();
        let sponsored = paymasters.apply_sponsored_call(&applied.call).unwrap();
        assert_eq!(sponsored.sponsorship.sponsored_fee, 1);
        assert_eq!(sponsored.sponsorship.caller_commitment, bob_commitment);
        assert_eq!(sponsored.paymaster_after.balance, 2);
        assert_eq!(sponsored.paymaster_after.spent_amount, 1);
        assert_eq!(
            sponsored.paymaster_after.spent_by_caller[&bob_commitment],
            1
        );
        assert!(!sponsored
            .sponsorship
            .public_record()
            .to_string()
            .contains("bob-view-key"));

        let profile = execution_profile_from_resources(&[sponsored.fee_resource]);
        assert_eq!(profile.contract_call_count, 1);
        assert_eq!(profile.observed_fee_units, 1);
        assert_eq!(profile.local_fee_lane_count, 5);
    }

    #[test]
    fn paymaster_policy_enforces_allowed_callers_and_caps() {
        let mut contracts = ContractState::new();
        let contract = contracts
            .deploy_counter_contract("alice-view-key", 100, false)
            .unwrap();
        let mut paymasters = PaymasterState::new();
        let paymaster = paymasters
            .create_paymaster(
                &contract.contract_id,
                "wxmr-rust",
                "alice-view-key",
                PaymasterPolicy {
                    per_call_cap: 1,
                    per_caller_cap: 1,
                    allowed_caller_commitments: vec![paymaster_caller_commitment("bob-view-key")],
                    ..PaymasterPolicy::default()
                },
            )
            .unwrap();
        paymasters
            .submit_deposit(
                &paymaster.paymaster_id,
                "alice-fee-note-1",
                3,
                "alice-view-key",
            )
            .unwrap();

        let bob_call = contracts
            .execute_contract_call(
                ContractCallRequest::new(
                    &contract.contract_id,
                    "increment",
                    json!({"amount": 1}),
                    "bob-view-key",
                    20,
                )
                .fee_asset("wxmr-rust", Some(1))
                .paymaster(&paymaster.paymaster_id),
            )
            .unwrap();
        paymasters.apply_sponsored_call(&bob_call.call).unwrap();

        let second_bob_call = contracts
            .execute_contract_call(
                ContractCallRequest::new(
                    &contract.contract_id,
                    "increment",
                    json!({"amount": 1}),
                    "bob-view-key",
                    20,
                )
                .fee_asset("wxmr-rust", Some(1))
                .paymaster(&paymaster.paymaster_id),
            )
            .unwrap();
        assert_eq!(
            paymasters
                .apply_sponsored_call(&second_bob_call.call)
                .unwrap_err(),
            "paymaster per-caller cap exceeded"
        );

        let carol_call = contracts
            .execute_contract_call(
                ContractCallRequest::new(
                    &contract.contract_id,
                    "increment",
                    json!({"amount": 1}),
                    "carol-view-key",
                    20,
                )
                .fee_asset("wxmr-rust", Some(1))
                .paymaster(&paymaster.paymaster_id),
            )
            .unwrap();
        assert_eq!(
            paymasters
                .apply_sponsored_call(&carol_call.call)
                .unwrap_err(),
            "caller is not allowed by paymaster policy"
        );
    }

    #[test]
    fn governance_can_pause_resume_and_update_policy() {
        let mut paymasters = PaymasterState::new();
        let paymaster = paymasters
            .create_paymaster(
                "contract-1",
                "wxmr-rust",
                "alice-view-key",
                PaymasterPolicy::default(),
            )
            .unwrap();
        let pause = paymasters
            .pause_paymaster(&paymaster.paymaster_id, "alice-view-key", "maintenance")
            .unwrap();
        assert_eq!(pause.action, "pause");
        assert_eq!(
            paymasters.paymasters[&paymaster.paymaster_id].status,
            "paused"
        );
        assert!(verify_authorization(
            "alice-view-key",
            "paymaster_governance_action",
            &pause.unsigned_record(),
            &pause.authorization,
        ));

        let resume = paymasters
            .resume_paymaster(&paymaster.paymaster_id, "alice-view-key")
            .unwrap();
        assert_eq!(resume.new_status, "active");
        let updated = paymasters
            .update_policy(
                &paymaster.paymaster_id,
                "alice-view-key",
                PaymasterPolicy {
                    per_call_cap: 3,
                    per_caller_cap: 5,
                    relayer_reward_budget: 9,
                    ..PaymasterPolicy::default()
                },
            )
            .unwrap();
        assert_eq!(updated.action, "update_policy");
        assert_eq!(
            paymasters.paymasters[&paymaster.paymaster_id]
                .policy
                .per_call_cap,
            3
        );
        assert_eq!(paymasters.governance_actions.len(), 3);
    }

    #[test]
    fn relayer_rewards_and_slashing_are_rooted() {
        let mut paymasters = PaymasterState::new();
        let paymaster = paymasters
            .create_paymaster(
                "contract-1",
                "wxmr-rust",
                "alice-view-key",
                PaymasterPolicy {
                    relayer_reward_units: 2,
                    relayer_reward_budget: 5,
                    ..PaymasterPolicy::default()
                },
            )
            .unwrap();
        let bond = paymasters
            .bond_relayer("relayer-1", "wxmr-rust", "relayer-bond-note-1", 4)
            .unwrap();
        assert!(!bond.public_record().to_string().contains("relayer-1"));

        let reward = paymasters
            .record_relayer_reward(&paymaster.paymaster_id, "relayer-1", 7, "deposit-tx-hash")
            .unwrap();
        assert_eq!(reward.reward_units, 2);
        assert_eq!(
            paymasters.paymasters[&paymaster.paymaster_id]
                .policy
                .relayer_reward_budget,
            3
        );

        let hook = paymasters
            .publish_slashing_hook(
                &paymaster.paymaster_id,
                "relayer-1",
                "watcher-1",
                "missed-refill",
                &json!({"authorization_id": "auth-1", "expired": true}),
            )
            .unwrap();
        assert_eq!(hook.penalty_units, 2);
        assert!(!hook.public_record().to_string().contains("watcher-1"));
        let settlement = paymasters.settle_slashing_hook(&hook.hook_id).unwrap();
        assert_eq!(settlement.slashed_amount, 2);
        assert_eq!(paymasters.relayer_bonds[&bond.bond_id].active_amount, 2);
        assert_eq!(paymasters.relayer_bonds[&bond.bond_id].slash_count, 1);
        assert_eq!(paymasters.slashing_hooks[&hook.hook_id].status, "settled");
        assert_eq!(paymasters.relayer_root().len(), 64);
        assert_eq!(paymasters.state_root().len(), 64);
    }
}
