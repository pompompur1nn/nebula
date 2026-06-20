use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingSettlementReceiptVaultRebateRuntimeResult<
    T,
> = std::result::Result<T, String>;
pub type Result<T> =
    PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingSettlementReceiptVaultRebateRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_SETTLEMENT_RECEIPT_VAULT_REBATE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-netting-settlement-receipt-vault-rebate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_SETTLEMENT_RECEIPT_VAULT_REBATE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VAULT_SUITE: &str =
    "pq-confidential-contract-sealed-storage-receipt-fee-netting-settlement-receipt-vault-rebate-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-contract-receipt-vault-rebate-public-record-v1";
pub const RECEIPT_CUSTODY_SCHEME: &str = "rebate-sealed-receipt-private-custody-root-v1";
pub const STORAGE_COMMITMENT_SCHEME: &str = "rebate-vault-storage-commitment-root-v1";
pub const CONTRACT_AUTHORIZATION_SCHEME: &str = "rebate-pq-contract-authorization-root-v1";
pub const CONTRACT_ATTESTATION_SCHEME: &str = "rebate-pq-contract-attestation-root-v1";
pub const VAULT_SEAL_SCHEME: &str = "rebate-receipt-vault-seal-root-v1";
pub const NET_SETTLEMENT_SCHEME: &str = "rebate-receipt-vault-fee-net-settlement-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "rebate-receipt-vault-low-fee-rebate-root-v1";
pub const LOW_FEE_CLAIM_SCHEME: &str = "rebate-receipt-vault-low-fee-claim-root-v1";
pub const DISCLOSURE_BUDGET_SCHEME: &str = "rebate-receipt-vault-disclosure-budget-root-v1";
pub const QUARANTINE_SCHEME: &str = "rebate-receipt-vault-quarantine-root-v1";
pub const NULLIFIER_SCHEME: &str = "rebate-receipt-vault-nullifier-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str = "rebate-receipt-vault-roots-only-public-record-root-v1";
pub const POLICY_ROOT_SCHEME: &str = "rebate-receipt-vault-privacy-pq-policy-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 6_032_170;
pub const DEVNET_EPOCH: u64 = 11_842;
pub const DEFAULT_MAX_RECEIPTS_PER_VAULT: usize = 24_576;
pub const DEFAULT_MAX_STORAGE_ROOTS_PER_RECEIPT: usize = 32;
pub const DEFAULT_MAX_AUTHORIZATIONS: usize = 8_192;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 16_384;
pub const DEFAULT_MAX_NETTING_SETS: usize = 4_096;
pub const DEFAULT_MAX_REBATES: usize = 16_384;
pub const DEFAULT_MAX_DISCLOSURE_BUDGETS: usize = 2_048;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_MICRO_FEE: u64 = 2;
pub const DEFAULT_MIN_MICRO_FEE: u64 = 1;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 2;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 24;
pub const DEFAULT_STORAGE_COMPRESSION_REBATE_BPS: u64 = 9;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 128;
pub const DEFAULT_DISCLOSURE_BUDGET_UNITS: u64 = 32;
pub const WAVE: u64 = 71;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultLane {
    ContractExecution,
    DefiSettlement,
    BridgeCustody,
    OracleDelivery,
    RecoveryReceipt,
    GovernanceReceipt,
    BatchMaintenance,
}

impl VaultLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractExecution => "contract_execution",
            Self::DefiSettlement => "defi_settlement",
            Self::BridgeCustody => "bridge_custody",
            Self::OracleDelivery => "oracle_delivery",
            Self::RecoveryReceipt => "recovery_receipt",
            Self::GovernanceReceipt => "governance_receipt",
            Self::BatchMaintenance => "batch_maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyStatus {
    Deposited,
    Authorized,
    Attested,
    Sealed,
    Netted,
    RebateAllocated,
    Quarantined,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    ReplayNullifier,
    MissingAuthorization,
    WeakPqAttestation,
    StorageRootMismatch,
    DisclosureBudgetExceeded,
    FeeSettlementMismatch,
    OperatorChallenge,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayNullifier => "replay_nullifier",
            Self::MissingAuthorization => "missing_authorization",
            Self::WeakPqAttestation => "weak_pq_attestation",
            Self::StorageRootMismatch => "storage_root_mismatch",
            Self::DisclosureBudgetExceeded => "disclosure_budget_exceeded",
            Self::FeeSettlementMismatch => "fee_settlement_mismatch",
            Self::OperatorChallenge => "operator_challenge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub vault_suite: String,
    pub roots_only_public_record_suite: String,
    pub max_receipts_per_vault: usize,
    pub max_storage_roots_per_receipt: usize,
    pub max_authorizations: usize,
    pub max_attestations: usize,
    pub max_netting_sets: usize,
    pub max_rebates: usize,
    pub max_disclosure_budgets: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_micro_fee: u64,
    pub min_micro_fee: u64,
    pub operator_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub storage_compression_rebate_bps: u64,
    pub quarantine_blocks: u64,
    pub default_disclosure_budget_units: u64,
    pub require_roots_only_public_records: bool,
    pub require_pq_contract_attestation: bool,
    pub require_replay_nullifier: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            vault_suite: VAULT_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            max_receipts_per_vault: DEFAULT_MAX_RECEIPTS_PER_VAULT,
            max_storage_roots_per_receipt: DEFAULT_MAX_STORAGE_ROOTS_PER_RECEIPT,
            max_authorizations: DEFAULT_MAX_AUTHORIZATIONS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_netting_sets: DEFAULT_MAX_NETTING_SETS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_disclosure_budgets: DEFAULT_MAX_DISCLOSURE_BUDGETS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_micro_fee: DEFAULT_BASE_MICRO_FEE,
            min_micro_fee: DEFAULT_MIN_MICRO_FEE,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            storage_compression_rebate_bps: DEFAULT_STORAGE_COMPRESSION_REBATE_BPS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            default_disclosure_budget_units: DEFAULT_DISCLOSURE_BUDGET_UNITS,
            require_roots_only_public_records: true,
            require_pq_contract_attestation: true,
            require_replay_nullifier: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("receipt vault protocol version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("receipt vault schema version mismatch".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("invalid receipt vault privacy set sizing".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("receipt vault pq security below policy".to_string());
        }
        if self.operator_fee_bps > MAX_BPS
            || self.low_fee_rebate_bps > MAX_BPS
            || self.storage_compression_rebate_bps > MAX_BPS
        {
            return Err("receipt vault bps value exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "vault_suite": self.vault_suite,
            "roots_only_public_record_suite": self.roots_only_public_record_suite,
            "max_receipts_per_vault": self.max_receipts_per_vault,
            "max_storage_roots_per_receipt": self.max_storage_roots_per_receipt,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_micro_fee": self.base_micro_fee,
            "min_micro_fee": self.min_micro_fee,
            "operator_fee_bps": self.operator_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "storage_compression_rebate_bps": self.storage_compression_rebate_bps,
            "quarantine_blocks": self.quarantine_blocks,
            "roots_only": self.require_roots_only_public_records,
            "pq_contract_attestation_required": self.require_pq_contract_attestation,
            "replay_nullifier_required": self.require_replay_nullifier,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sealed_receipts_deposited: u64,
    pub receipt_custody_records: u64,
    pub storage_commitment_roots_bound: u64,
    pub contracts_authorized: u64,
    pub pq_contract_attestations_recorded: u64,
    pub vaults_sealed: u64,
    pub settlement_netting_sets_opened: u64,
    pub receipts_netted: u64,
    pub gross_micro_fees_deposited: u64,
    pub net_micro_fees_settled: u64,
    pub operator_micro_fees_accrued: u64,
    pub low_fee_rebates_allocated: u64,
    pub low_fee_claims_recorded: u64,
    pub rebate_micro_fees_allocated: u64,
    pub claimed_rebate_micro_fees: u64,
    pub disclosure_budgets_opened: u64,
    pub disclosure_units_reserved: u64,
    pub disclosure_units_spent: u64,
    pub receipts_quarantined: u64,
    pub receipts_released: u64,
    pub duplicate_nullifiers_rejected: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sealed_receipts_deposited": self.sealed_receipts_deposited,
            "receipt_custody_records": self.receipt_custody_records,
            "storage_commitment_roots_bound": self.storage_commitment_roots_bound,
            "contracts_authorized": self.contracts_authorized,
            "pq_contract_attestations_recorded": self.pq_contract_attestations_recorded,
            "vaults_sealed": self.vaults_sealed,
            "settlement_netting_sets_opened": self.settlement_netting_sets_opened,
            "receipts_netted": self.receipts_netted,
            "gross_micro_fees_deposited": self.gross_micro_fees_deposited,
            "net_micro_fees_settled": self.net_micro_fees_settled,
            "operator_micro_fees_accrued": self.operator_micro_fees_accrued,
            "low_fee_rebates_allocated": self.low_fee_rebates_allocated,
            "low_fee_claims_recorded": self.low_fee_claims_recorded,
            "rebate_micro_fees_allocated": self.rebate_micro_fees_allocated,
            "claimed_rebate_micro_fees": self.claimed_rebate_micro_fees,
            "disclosure_budgets_opened": self.disclosure_budgets_opened,
            "disclosure_units_reserved": self.disclosure_units_reserved,
            "disclosure_units_spent": self.disclosure_units_spent,
            "receipts_quarantined": self.receipts_quarantined,
            "receipts_released": self.receipts_released,
            "duplicate_nullifiers_rejected": self.duplicate_nullifiers_rejected,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub receipt_custody_root: String,
    pub storage_commitment_root: String,
    pub contract_authorization_root: String,
    pub contract_attestation_root: String,
    pub vault_seal_root: String,
    pub net_settlement_root: String,
    pub low_fee_rebate_root: String,
    pub low_fee_claim_root: String,
    pub disclosure_budget_root: String,
    pub quarantine_root: String,
    pub nullifier_root: String,
    pub policy_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("rebate-receipt-vault-config-root-v1"),
            counters_root: empty_root("rebate-receipt-vault-counters-root-v1"),
            receipt_custody_root: empty_root(RECEIPT_CUSTODY_SCHEME),
            storage_commitment_root: empty_root(STORAGE_COMMITMENT_SCHEME),
            contract_authorization_root: empty_root(CONTRACT_AUTHORIZATION_SCHEME),
            contract_attestation_root: empty_root(CONTRACT_ATTESTATION_SCHEME),
            vault_seal_root: empty_root(VAULT_SEAL_SCHEME),
            net_settlement_root: empty_root(NET_SETTLEMENT_SCHEME),
            low_fee_rebate_root: empty_root(LOW_FEE_REBATE_SCHEME),
            low_fee_claim_root: empty_root(LOW_FEE_CLAIM_SCHEME),
            disclosure_budget_root: empty_root(DISCLOSURE_BUDGET_SCHEME),
            quarantine_root: empty_root(QUARANTINE_SCHEME),
            nullifier_root: empty_root(NULLIFIER_SCHEME),
            policy_root: empty_root(POLICY_ROOT_SCHEME),
            public_record_root: empty_root(PUBLIC_RECORD_ROOT_SCHEME),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> BTreeMap<String, String> {
        [
            ("config_root", self.config_root.clone()),
            ("counters_root", self.counters_root.clone()),
            ("receipt_custody_root", self.receipt_custody_root.clone()),
            (
                "storage_commitment_root",
                self.storage_commitment_root.clone(),
            ),
            (
                "contract_authorization_root",
                self.contract_authorization_root.clone(),
            ),
            (
                "contract_attestation_root",
                self.contract_attestation_root.clone(),
            ),
            ("vault_seal_root", self.vault_seal_root.clone()),
            ("net_settlement_root", self.net_settlement_root.clone()),
            ("low_fee_rebate_root", self.low_fee_rebate_root.clone()),
            ("low_fee_claim_root", self.low_fee_claim_root.clone()),
            (
                "disclosure_budget_root",
                self.disclosure_budget_root.clone(),
            ),
            ("quarantine_root", self.quarantine_root.clone()),
            ("nullifier_root", self.nullifier_root.clone()),
            ("policy_root", self.policy_root.clone()),
            ("public_record_root", self.public_record_root.clone()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedReceiptDepositInput {
    pub lane: VaultLane,
    pub contract_id_commitment: String,
    pub caller_commitment: String,
    pub receipt_ciphertext_root: String,
    pub receipt_commitment: String,
    pub storage_commitment_roots: Vec<String>,
    pub replay_nullifier: String,
    pub gross_micro_fee: u64,
    pub receipt_bytes: u64,
    pub storage_keys: u64,
    pub privacy_set_size: u64,
    pub deposit_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractAuthorizationInput {
    pub receipt_id: String,
    pub contract_id_commitment: String,
    pub authorized_method_root: String,
    pub authority_committee_root: String,
    pub policy_root: String,
    pub expires_at_height: u64,
    pub authorization_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractAttestationInput {
    pub receipt_id: String,
    pub contract_id_commitment: String,
    pub attester_committee_root: String,
    pub pq_signature_commitment: String,
    pub execution_trace_commitment: String,
    pub storage_delta_commitment: String,
    pub pq_security_bits: u16,
    pub attestation_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultSealInput {
    pub receipt_ids: Vec<String>,
    pub vault_operator_commitment: String,
    pub custody_committee_root: String,
    pub storage_commitment_root: String,
    pub sealed_epoch: u64,
    pub seal_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementNettingInput {
    pub vault_seal_id: String,
    pub receipt_ids: Vec<String>,
    pub settlement_asset_root: String,
    pub netting_commitment_root: String,
    pub fee_liability_root: String,
    pub compression_ratio_bps: u64,
    pub settlement_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAllocationInput {
    pub settlement_id: String,
    pub receipt_id: String,
    pub rebate_recipient_commitment: String,
    pub rebate_policy_root: String,
    pub extra_rebate_micro_fee: u64,
    pub allocation_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeClaimInput {
    pub rebate_id: String,
    pub claim_commitment: String,
    pub claimant_commitment: String,
    pub payout_address_commitment: String,
    pub claim_nullifier: String,
    pub claim_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureBudgetInput {
    pub contract_id_commitment: String,
    pub receipt_scope_root: String,
    pub auditor_commitment: String,
    pub budget_units: u64,
    pub expires_at_height: u64,
    pub budget_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureSpendInput {
    pub budget_id: String,
    pub receipt_id: String,
    pub disclosure_commitment_root: String,
    pub units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineInput {
    pub receipt_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub release_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedReceiptCustody {
    pub id: String,
    pub lane: VaultLane,
    pub contract_id_commitment: String,
    pub caller_commitment: String,
    pub receipt_ciphertext_root: String,
    pub receipt_commitment: String,
    pub storage_commitment_roots: Vec<String>,
    pub storage_commitment_root: String,
    pub replay_nullifier: String,
    pub gross_micro_fee: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub receipt_bytes: u64,
    pub storage_keys: u64,
    pub privacy_set_size: u64,
    pub status: CustodyStatus,
    pub deposited_at_height: u64,
}

impl SealedReceiptCustody {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "lane": self.lane.as_str(),
            "contract_id_commitment": self.contract_id_commitment,
            "caller_commitment": self.caller_commitment,
            "receipt_ciphertext_root": self.receipt_ciphertext_root,
            "receipt_commitment": self.receipt_commitment,
            "storage_commitment_root": self.storage_commitment_root,
            "fee_commitment": fee_commitment(self.gross_micro_fee, self.net_micro_fee, self.rebate_micro_fee),
            "receipt_bytes": self.receipt_bytes,
            "storage_keys": self.storage_keys,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "deposited_at_height": self.deposited_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractAuthorization {
    pub id: String,
    pub receipt_id: String,
    pub contract_id_commitment: String,
    pub authorized_method_root: String,
    pub authority_committee_root: String,
    pub policy_root: String,
    pub expires_at_height: u64,
}

impl ContractAuthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "receipt_id": self.receipt_id,
            "contract_id_commitment": self.contract_id_commitment,
            "authorized_method_root": self.authorized_method_root,
            "authority_committee_root": self.authority_committee_root,
            "policy_root": self.policy_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractAttestation {
    pub id: String,
    pub receipt_id: String,
    pub contract_id_commitment: String,
    pub attester_committee_root: String,
    pub pq_signature_commitment: String,
    pub execution_trace_commitment: String,
    pub storage_delta_commitment: String,
    pub pq_security_bits: u16,
}

impl ContractAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "receipt_id": self.receipt_id,
            "contract_id_commitment": self.contract_id_commitment,
            "attester_committee_root": self.attester_committee_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "execution_trace_commitment": self.execution_trace_commitment,
            "storage_delta_commitment": self.storage_delta_commitment,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultSeal {
    pub id: String,
    pub receipt_ids: Vec<String>,
    pub vault_operator_commitment: String,
    pub custody_committee_root: String,
    pub storage_commitment_root: String,
    pub sealed_epoch: u64,
    pub sealed_at_height: u64,
}

impl VaultSeal {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "receipt_set_root": string_list_root("RECEIPT-VAULT:SEAL-RECEIPT-SET", &self.receipt_ids),
            "vault_operator_commitment": self.vault_operator_commitment,
            "custody_committee_root": self.custody_committee_root,
            "storage_commitment_root": self.storage_commitment_root,
            "sealed_epoch": self.sealed_epoch,
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetSettlement {
    pub id: String,
    pub vault_seal_id: String,
    pub receipt_ids: Vec<String>,
    pub settlement_asset_root: String,
    pub netting_commitment_root: String,
    pub fee_liability_root: String,
    pub gross_micro_fee: u64,
    pub net_micro_fee: u64,
    pub operator_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub compression_ratio_bps: u64,
}

impl NetSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "vault_seal_id": self.vault_seal_id,
            "receipt_set_root": string_list_root("RECEIPT-VAULT:NET-SETTLEMENT-RECEIPTS", &self.receipt_ids),
            "settlement_asset_root": self.settlement_asset_root,
            "netting_commitment_root": self.netting_commitment_root,
            "fee_liability_root": self.fee_liability_root,
            "fee_commitment": fee_commitment(self.gross_micro_fee, self.net_micro_fee, self.rebate_micro_fee),
            "operator_fee_commitment": payload_root("RECEIPT-VAULT:OPERATOR-FEE-COMMITMENT", &json!({ "micro_fee": self.operator_micro_fee })),
            "compression_ratio_bps": self.compression_ratio_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub id: String,
    pub settlement_id: String,
    pub receipt_id: String,
    pub rebate_recipient_commitment: String,
    pub rebate_policy_root: String,
    pub rebate_micro_fee: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "settlement_id": self.settlement_id,
            "receipt_id": self.receipt_id,
            "rebate_recipient_commitment": self.rebate_recipient_commitment,
            "rebate_policy_root": self.rebate_policy_root,
            "rebate_commitment": payload_root("RECEIPT-VAULT:REBATE-COMMITMENT", &json!({ "micro_fee": self.rebate_micro_fee })),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeClaim {
    pub id: String,
    pub rebate_id: String,
    pub receipt_id: String,
    pub claim_commitment: String,
    pub claimant_commitment: String,
    pub payout_address_commitment: String,
    pub claim_nullifier: String,
    pub rebate_micro_fee: u64,
    pub claimed_at_height: u64,
}

impl LowFeeClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "claim_commitment": self.claim_commitment,
            "claimant_commitment": self.claimant_commitment,
            "payout_address_commitment": self.payout_address_commitment,
            "claim_nullifier_commitment": payload_root("RECEIPT-VAULT-REBATE:CLAIM-NULLIFIER", &json!({ "nullifier": self.claim_nullifier })),
            "rebate_commitment": payload_root("RECEIPT-VAULT-REBATE:CLAIM-AMOUNT", &json!({ "micro_fee": self.rebate_micro_fee })),
            "claimed_at_height": self.claimed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureBudget {
    pub id: String,
    pub contract_id_commitment: String,
    pub receipt_scope_root: String,
    pub auditor_commitment: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub expires_at_height: u64,
}

impl DisclosureBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "contract_id_commitment": self.contract_id_commitment,
            "receipt_scope_root": self.receipt_scope_root,
            "auditor_commitment": self.auditor_commitment,
            "budget_units_commitment": payload_root("RECEIPT-VAULT:DISCLOSURE-BUDGET-UNITS", &json!({ "budget": self.budget_units, "spent": self.spent_units })),
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub id: String,
    pub receipt_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub release_height: u64,
    pub resolved: bool,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "receipt_id": self.receipt_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "release_height": self.release_height,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub receipt_custody: BTreeMap<String, SealedReceiptCustody>,
    pub contract_authorizations: BTreeMap<String, ContractAuthorization>,
    pub contract_attestations: BTreeMap<String, ContractAttestation>,
    pub vault_seals: BTreeMap<String, VaultSeal>,
    pub net_settlements: BTreeMap<String, NetSettlement>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub low_fee_claims: BTreeMap<String, LowFeeClaim>,
    pub disclosure_budgets: BTreeMap<String, DisclosureBudget>,
    pub quarantine_records: BTreeMap<String, QuarantineRecord>,
    pub replay_nullifiers: BTreeSet<String>,
    pub policy_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            receipt_custody: BTreeMap::new(),
            contract_authorizations: BTreeMap::new(),
            contract_attestations: BTreeMap::new(),
            vault_seals: BTreeMap::new(),
            net_settlements: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            low_fee_claims: BTreeMap::new(),
            disclosure_budgets: BTreeMap::new(),
            quarantine_records: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
            policy_roots: BTreeSet::new(),
        };
        state.policy_roots.insert(state.policy_root());
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet receipt vault config is valid");
        let budget_id = state
            .open_disclosure_budget(DisclosureBudgetInput {
                contract_id_commitment: "contract:commitment:private-dex-vault".to_string(),
                receipt_scope_root: "receipt:scope:root:devnet-vault".to_string(),
                auditor_commitment: "auditor:commitment:pq-privacy-council".to_string(),
                budget_units: DEFAULT_DISCLOSURE_BUDGET_UNITS,
                expires_at_height: DEVNET_HEIGHT + 720,
                budget_nonce: 1,
            })
            .expect("devnet disclosure budget opens");
        let receipt_id = state
            .deposit_sealed_receipt(SealedReceiptDepositInput {
                lane: VaultLane::DefiSettlement,
                contract_id_commitment: "contract:commitment:private-dex-vault".to_string(),
                caller_commitment: "caller:commitment:devnet-liquidity-provider".to_string(),
                receipt_ciphertext_root: "ciphertext:root:receipt-0".to_string(),
                receipt_commitment: "receipt:commitment:devnet-0".to_string(),
                storage_commitment_roots: vec![
                    "storage:commitment:pre-state-devnet-0".to_string(),
                    "storage:commitment:post-state-devnet-0".to_string(),
                ],
                replay_nullifier: "nullifier:receipt:vault:devnet-0".to_string(),
                gross_micro_fee: 144,
                receipt_bytes: 4096,
                storage_keys: 64,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                deposit_nonce: 1,
            })
            .expect("devnet receipt deposits");
        state
            .authorize_contract(ContractAuthorizationInput {
                receipt_id: receipt_id.clone(),
                contract_id_commitment: "contract:commitment:private-dex-vault".to_string(),
                authorized_method_root: "method:root:swap-settle".to_string(),
                authority_committee_root: "committee:root:pq-contract-authority-devnet".to_string(),
                policy_root: state.policy_root(),
                expires_at_height: DEVNET_HEIGHT + 512,
                authorization_nonce: 1,
            })
            .expect("devnet contract authorizes");
        state
            .record_contract_attestation(ContractAttestationInput {
                receipt_id: receipt_id.clone(),
                contract_id_commitment: "contract:commitment:private-dex-vault".to_string(),
                attester_committee_root: "committee:root:pq-attesters-devnet".to_string(),
                pq_signature_commitment: "pq:sig:commitment:receipt-0".to_string(),
                execution_trace_commitment: "trace:commitment:private-swap-0".to_string(),
                storage_delta_commitment: "storage:delta:commitment:private-swap-0".to_string(),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                attestation_nonce: 1,
            })
            .expect("devnet attestation records");
        let seal_id = state
            .seal_vault(VaultSealInput {
                receipt_ids: vec![receipt_id.clone()],
                vault_operator_commitment: "operator:commitment:receipt-vault-devnet".to_string(),
                custody_committee_root: "committee:root:receipt-vault-custody-devnet".to_string(),
                storage_commitment_root: state.roots.storage_commitment_root.clone(),
                sealed_epoch: DEVNET_EPOCH,
                seal_nonce: 1,
            })
            .expect("devnet vault seals");
        let settlement_id = state
            .net_settlement(SettlementNettingInput {
                vault_seal_id: seal_id,
                receipt_ids: vec![receipt_id.clone()],
                settlement_asset_root: "asset:root:piconero-devnet".to_string(),
                netting_commitment_root: "netting:commitment:root:devnet-vault-0".to_string(),
                fee_liability_root: "fee:liability:root:devnet-vault-0".to_string(),
                compression_ratio_bps: 7_500,
                settlement_nonce: 1,
            })
            .expect("devnet settlement nets");
        let rebate_id = state
            .allocate_rebate(RebateAllocationInput {
                settlement_id,
                receipt_id: receipt_id.clone(),
                rebate_recipient_commitment: "rebate:recipient:commitment:lp-0".to_string(),
                rebate_policy_root: state.policy_root(),
                extra_rebate_micro_fee: 1,
                allocation_nonce: 1,
            })
            .expect("devnet rebate allocates");
        state
            .claim_low_fee_rebate(LowFeeClaimInput {
                rebate_id,
                claim_commitment: "rebate:claim:commitment:lp-0".to_string(),
                claimant_commitment: "claimant:commitment:lp-0".to_string(),
                payout_address_commitment: "payout:address:commitment:lp-0".to_string(),
                claim_nullifier: "nullifier:rebate:claim:devnet-0".to_string(),
                claim_nonce: 1,
            })
            .expect("devnet rebate claim records");
        state
            .spend_disclosure_budget(DisclosureSpendInput {
                budget_id,
                receipt_id,
                disclosure_commitment_root: "disclosure:commitment:root:devnet-audit-0".to_string(),
                units: 2,
            })
            .expect("devnet disclosure spends");
        state
    }

    pub fn policy_root(&self) -> String {
        payload_root(
            POLICY_ROOT_SCHEME,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "roots_only": self.config.require_roots_only_public_records,
                "pq_contract_attestation_required": self.config.require_pq_contract_attestation,
                "replay_nullifier_required": self.config.require_replay_nullifier,
            }),
        )
    }

    pub fn deposit_sealed_receipt(&mut self, input: SealedReceiptDepositInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty("contract_id_commitment", &input.contract_id_commitment)?;
        require_non_empty("caller_commitment", &input.caller_commitment)?;
        require_non_empty("receipt_ciphertext_root", &input.receipt_ciphertext_root)?;
        require_non_empty("receipt_commitment", &input.receipt_commitment)?;
        require_non_empty("replay_nullifier", &input.replay_nullifier)?;
        if input.storage_commitment_roots.is_empty()
            || input.storage_commitment_roots.len() > self.config.max_storage_roots_per_receipt
        {
            return Err("invalid receipt storage commitment root count".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("receipt privacy set below vault policy".to_string());
        }
        if self.receipt_custody.len() >= self.config.max_receipts_per_vault {
            return Err("receipt vault capacity exceeded".to_string());
        }
        if self.config.require_replay_nullifier
            && self.replay_nullifiers.contains(&input.replay_nullifier)
        {
            self.counters.duplicate_nullifiers_rejected = self
                .counters
                .duplicate_nullifiers_rejected
                .saturating_add(1);
            self.refresh_roots();
            return Err("receipt replay nullifier already consumed".to_string());
        }
        let storage_commitment_root = string_list_root(
            "RECEIPT-VAULT:RECEIPT-STORAGE-COMMITMENTS",
            &input.storage_commitment_roots,
        );
        let id = sealed_receipt_id(
            input.lane,
            &input.contract_id_commitment,
            &input.receipt_commitment,
            &input.replay_nullifier,
            input.deposit_nonce,
        );
        if self.receipt_custody.contains_key(&id) {
            return Err("sealed receipt already deposited".to_string());
        }
        let receipt = SealedReceiptCustody {
            id: id.clone(),
            lane: input.lane,
            contract_id_commitment: input.contract_id_commitment,
            caller_commitment: input.caller_commitment,
            receipt_ciphertext_root: input.receipt_ciphertext_root,
            receipt_commitment: input.receipt_commitment,
            storage_commitment_roots: input.storage_commitment_roots,
            storage_commitment_root,
            replay_nullifier: input.replay_nullifier.clone(),
            gross_micro_fee: input.gross_micro_fee.max(self.config.min_micro_fee),
            net_micro_fee: 0,
            rebate_micro_fee: 0,
            receipt_bytes: input.receipt_bytes,
            storage_keys: input.storage_keys,
            privacy_set_size: input.privacy_set_size,
            status: CustodyStatus::Deposited,
            deposited_at_height: self.height,
        };
        self.replay_nullifiers.insert(input.replay_nullifier);
        self.receipt_custody.insert(id.clone(), receipt);
        self.counters.sealed_receipts_deposited =
            self.counters.sealed_receipts_deposited.saturating_add(1);
        self.counters.receipt_custody_records =
            self.counters.receipt_custody_records.saturating_add(1);
        self.counters.storage_commitment_roots_bound = self
            .counters
            .storage_commitment_roots_bound
            .saturating_add(1);
        self.counters.gross_micro_fees_deposited = self
            .counters
            .gross_micro_fees_deposited
            .saturating_add(input.gross_micro_fee.max(self.config.min_micro_fee));
        self.refresh_roots();
        Ok(id)
    }

    pub fn authorize_contract(&mut self, input: ContractAuthorizationInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty("receipt_id", &input.receipt_id)?;
        require_non_empty("contract_id_commitment", &input.contract_id_commitment)?;
        require_non_empty("authorized_method_root", &input.authorized_method_root)?;
        require_non_empty("authority_committee_root", &input.authority_committee_root)?;
        require_non_empty("policy_root", &input.policy_root)?;
        if self.contract_authorizations.len() >= self.config.max_authorizations {
            return Err("receipt vault authorization capacity exceeded".to_string());
        }
        let receipt = self
            .receipt_custody
            .get_mut(&input.receipt_id)
            .ok_or_else(|| "receipt missing for contract authorization".to_string())?;
        if receipt.contract_id_commitment != input.contract_id_commitment {
            return Err("contract authorization commitment mismatch".to_string());
        }
        if input.expires_at_height <= self.height {
            return Err("contract authorization already expired".to_string());
        }
        let id = contract_authorization_id(
            &input.receipt_id,
            &input.contract_id_commitment,
            &input.authorized_method_root,
            input.authorization_nonce,
        );
        let authorization = ContractAuthorization {
            id: id.clone(),
            receipt_id: input.receipt_id,
            contract_id_commitment: input.contract_id_commitment,
            authorized_method_root: input.authorized_method_root,
            authority_committee_root: input.authority_committee_root,
            policy_root: input.policy_root,
            expires_at_height: input.expires_at_height,
        };
        receipt.status = CustodyStatus::Authorized;
        self.contract_authorizations
            .insert(id.clone(), authorization);
        self.counters.contracts_authorized = self.counters.contracts_authorized.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_contract_attestation(
        &mut self,
        input: ContractAttestationInput,
    ) -> Result<String> {
        self.config.validate()?;
        require_non_empty("receipt_id", &input.receipt_id)?;
        require_non_empty("contract_id_commitment", &input.contract_id_commitment)?;
        require_non_empty("attester_committee_root", &input.attester_committee_root)?;
        require_non_empty("pq_signature_commitment", &input.pq_signature_commitment)?;
        require_non_empty(
            "execution_trace_commitment",
            &input.execution_trace_commitment,
        )?;
        require_non_empty("storage_delta_commitment", &input.storage_delta_commitment)?;
        if self.contract_attestations.len() >= self.config.max_attestations {
            return Err("receipt vault attestation capacity exceeded".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("contract attestation pq security below policy".to_string());
        }
        let receipt = self
            .receipt_custody
            .get_mut(&input.receipt_id)
            .ok_or_else(|| "receipt missing for contract attestation".to_string())?;
        if receipt.contract_id_commitment != input.contract_id_commitment {
            return Err("contract attestation commitment mismatch".to_string());
        }
        let id = contract_attestation_id(
            &input.receipt_id,
            &input.contract_id_commitment,
            &input.pq_signature_commitment,
            input.attestation_nonce,
        );
        let attestation = ContractAttestation {
            id: id.clone(),
            receipt_id: input.receipt_id,
            contract_id_commitment: input.contract_id_commitment,
            attester_committee_root: input.attester_committee_root,
            pq_signature_commitment: input.pq_signature_commitment,
            execution_trace_commitment: input.execution_trace_commitment,
            storage_delta_commitment: input.storage_delta_commitment,
            pq_security_bits: input.pq_security_bits,
        };
        receipt.status = CustodyStatus::Attested;
        self.contract_attestations.insert(id.clone(), attestation);
        self.counters.pq_contract_attestations_recorded = self
            .counters
            .pq_contract_attestations_recorded
            .saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn seal_vault(&mut self, input: VaultSealInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty(
            "vault_operator_commitment",
            &input.vault_operator_commitment,
        )?;
        require_non_empty("custody_committee_root", &input.custody_committee_root)?;
        require_non_empty("storage_commitment_root", &input.storage_commitment_root)?;
        if input.receipt_ids.is_empty() {
            return Err("vault seal requires at least one receipt".to_string());
        }
        let mut receipt_storage_roots = Vec::new();
        for receipt_id in &input.receipt_ids {
            let receipt = self
                .receipt_custody
                .get(receipt_id)
                .ok_or_else(|| format!("receipt {receipt_id} missing for vault seal"))?;
            if matches!(
                receipt.status,
                CustodyStatus::Quarantined | CustodyStatus::Released
            ) {
                return Err(format!("receipt {receipt_id} cannot be sealed"));
            }
            if self.config.require_pq_contract_attestation
                && !self
                    .contract_attestations
                    .values()
                    .any(|attestation| attestation.receipt_id == *receipt_id)
            {
                return Err(format!(
                    "receipt {receipt_id} lacks pq contract attestation"
                ));
            }
            receipt_storage_roots.push(receipt.storage_commitment_root.clone());
        }
        let computed_storage_root =
            string_list_root("RECEIPT-VAULT:SEAL-STORAGE-ROOTS", &receipt_storage_roots);
        if computed_storage_root != input.storage_commitment_root {
            return Err("vault seal storage commitment root mismatch".to_string());
        }
        let id = vault_seal_id(
            &input.receipt_ids,
            &input.vault_operator_commitment,
            &input.custody_committee_root,
            input.seal_nonce,
        );
        let seal = VaultSeal {
            id: id.clone(),
            receipt_ids: input.receipt_ids.clone(),
            vault_operator_commitment: input.vault_operator_commitment,
            custody_committee_root: input.custody_committee_root,
            storage_commitment_root: input.storage_commitment_root,
            sealed_epoch: input.sealed_epoch,
            sealed_at_height: self.height,
        };
        for receipt_id in &input.receipt_ids {
            if let Some(receipt) = self.receipt_custody.get_mut(receipt_id) {
                receipt.status = CustodyStatus::Sealed;
            }
        }
        self.vault_seals.insert(id.clone(), seal);
        self.counters.vaults_sealed = self.counters.vaults_sealed.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn net_settlement(&mut self, input: SettlementNettingInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty("vault_seal_id", &input.vault_seal_id)?;
        require_non_empty("settlement_asset_root", &input.settlement_asset_root)?;
        require_non_empty("netting_commitment_root", &input.netting_commitment_root)?;
        require_non_empty("fee_liability_root", &input.fee_liability_root)?;
        if self.net_settlements.len() >= self.config.max_netting_sets {
            return Err("receipt vault netting capacity exceeded".to_string());
        }
        let seal = self
            .vault_seals
            .get(&input.vault_seal_id)
            .ok_or_else(|| "vault seal missing for net settlement".to_string())?;
        if seal.receipt_ids != input.receipt_ids {
            return Err("net settlement receipt set does not match vault seal".to_string());
        }
        let mut gross_micro_fee = 0u64;
        for receipt_id in &input.receipt_ids {
            let receipt = self
                .receipt_custody
                .get(receipt_id)
                .ok_or_else(|| format!("receipt {receipt_id} missing for net settlement"))?;
            if receipt.status != CustodyStatus::Sealed {
                return Err(format!("receipt {receipt_id} is not sealed"));
            }
            gross_micro_fee = gross_micro_fee.saturating_add(receipt.gross_micro_fee);
        }
        let operator_micro_fee = bps(gross_micro_fee, self.config.operator_fee_bps);
        let low_fee_rebate = bps(gross_micro_fee, self.config.low_fee_rebate_bps);
        let compression_rebate = bps(
            gross_micro_fee,
            self.config
                .storage_compression_rebate_bps
                .saturating_mul(input.compression_ratio_bps.min(MAX_BPS))
                / MAX_BPS,
        );
        let rebate_micro_fee = low_fee_rebate.saturating_add(compression_rebate);
        let net_micro_fee = gross_micro_fee
            .saturating_sub(operator_micro_fee)
            .saturating_sub(rebate_micro_fee)
            .max(self.config.min_micro_fee);
        let id = net_settlement_id(
            &input.vault_seal_id,
            &input.netting_commitment_root,
            &input.fee_liability_root,
            input.settlement_nonce,
        );
        let settlement = NetSettlement {
            id: id.clone(),
            vault_seal_id: input.vault_seal_id,
            receipt_ids: input.receipt_ids.clone(),
            settlement_asset_root: input.settlement_asset_root,
            netting_commitment_root: input.netting_commitment_root,
            fee_liability_root: input.fee_liability_root,
            gross_micro_fee,
            net_micro_fee,
            operator_micro_fee,
            rebate_micro_fee,
            compression_ratio_bps: input.compression_ratio_bps.min(MAX_BPS),
        };
        for receipt_id in &input.receipt_ids {
            if let Some(receipt) = self.receipt_custody.get_mut(receipt_id) {
                let receipt_rebate =
                    proportional_share(receipt.gross_micro_fee, gross_micro_fee, rebate_micro_fee);
                receipt.rebate_micro_fee = receipt_rebate;
                receipt.net_micro_fee = receipt
                    .gross_micro_fee
                    .saturating_sub(proportional_share(
                        receipt.gross_micro_fee,
                        gross_micro_fee,
                        operator_micro_fee,
                    ))
                    .saturating_sub(receipt_rebate)
                    .max(self.config.min_micro_fee);
                receipt.status = CustodyStatus::Netted;
            }
        }
        self.net_settlements.insert(id.clone(), settlement);
        self.counters.settlement_netting_sets_opened = self
            .counters
            .settlement_netting_sets_opened
            .saturating_add(1);
        self.counters.receipts_netted = self
            .counters
            .receipts_netted
            .saturating_add(input.receipt_ids.len() as u64);
        self.counters.net_micro_fees_settled = self
            .counters
            .net_micro_fees_settled
            .saturating_add(net_micro_fee);
        self.counters.operator_micro_fees_accrued = self
            .counters
            .operator_micro_fees_accrued
            .saturating_add(operator_micro_fee);
        self.refresh_roots();
        Ok(id)
    }

    pub fn allocate_rebate(&mut self, input: RebateAllocationInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty("settlement_id", &input.settlement_id)?;
        require_non_empty("receipt_id", &input.receipt_id)?;
        require_non_empty(
            "rebate_recipient_commitment",
            &input.rebate_recipient_commitment,
        )?;
        require_non_empty("rebate_policy_root", &input.rebate_policy_root)?;
        if self.low_fee_rebates.len() >= self.config.max_rebates {
            return Err("receipt vault rebate capacity exceeded".to_string());
        }
        let settlement = self
            .net_settlements
            .get(&input.settlement_id)
            .ok_or_else(|| "net settlement missing for rebate allocation".to_string())?;
        if !settlement.receipt_ids.contains(&input.receipt_id) {
            return Err("rebate receipt is outside settlement set".to_string());
        }
        let receipt = self
            .receipt_custody
            .get_mut(&input.receipt_id)
            .ok_or_else(|| "receipt missing for rebate allocation".to_string())?;
        let rebate_micro_fee = receipt
            .rebate_micro_fee
            .saturating_add(input.extra_rebate_micro_fee);
        receipt.rebate_micro_fee = rebate_micro_fee;
        receipt.status = CustodyStatus::RebateAllocated;
        let id = rebate_id(
            &input.settlement_id,
            &input.receipt_id,
            &input.rebate_recipient_commitment,
            input.allocation_nonce,
        );
        let rebate = LowFeeRebate {
            id: id.clone(),
            settlement_id: input.settlement_id,
            receipt_id: input.receipt_id,
            rebate_recipient_commitment: input.rebate_recipient_commitment,
            rebate_policy_root: input.rebate_policy_root,
            rebate_micro_fee,
        };
        self.low_fee_rebates.insert(id.clone(), rebate);
        self.counters.low_fee_rebates_allocated =
            self.counters.low_fee_rebates_allocated.saturating_add(1);
        self.counters.rebate_micro_fees_allocated = self
            .counters
            .rebate_micro_fees_allocated
            .saturating_add(rebate_micro_fee);
        self.refresh_roots();
        Ok(id)
    }

    pub fn claim_low_fee_rebate(&mut self, input: LowFeeClaimInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty("rebate_id", &input.rebate_id)?;
        require_non_empty("claim_commitment", &input.claim_commitment)?;
        require_non_empty("claimant_commitment", &input.claimant_commitment)?;
        require_non_empty(
            "payout_address_commitment",
            &input.payout_address_commitment,
        )?;
        require_non_empty("claim_nullifier", &input.claim_nullifier)?;
        if self.replay_nullifiers.contains(&input.claim_nullifier) {
            self.counters.duplicate_nullifiers_rejected = self
                .counters
                .duplicate_nullifiers_rejected
                .saturating_add(1);
            self.refresh_roots();
            return Err("low fee rebate claim nullifier already consumed".to_string());
        }
        let rebate = self
            .low_fee_rebates
            .get(&input.rebate_id)
            .ok_or_else(|| "low fee rebate missing for claim".to_string())?;
        let receipt_id = rebate.receipt_id.clone();
        let rebate_micro_fee = rebate.rebate_micro_fee;
        let receipt = self
            .receipt_custody
            .get(&receipt_id)
            .ok_or_else(|| "rebate receipt missing for claim".to_string())?;
        if matches!(receipt.status, CustodyStatus::Quarantined) {
            return Err("quarantined receipt rebate cannot be claimed".to_string());
        }
        if self
            .low_fee_claims
            .values()
            .any(|claim| claim.rebate_id == input.rebate_id)
        {
            return Err("low fee rebate already claimed".to_string());
        }
        let id = low_fee_claim_id(
            &input.rebate_id,
            &input.claim_commitment,
            &input.claim_nullifier,
            input.claim_nonce,
        );
        let claim = LowFeeClaim {
            id: id.clone(),
            rebate_id: input.rebate_id,
            receipt_id,
            claim_commitment: input.claim_commitment,
            claimant_commitment: input.claimant_commitment,
            payout_address_commitment: input.payout_address_commitment,
            claim_nullifier: input.claim_nullifier.clone(),
            rebate_micro_fee,
            claimed_at_height: self.height,
        };
        self.replay_nullifiers.insert(input.claim_nullifier);
        self.low_fee_claims.insert(id.clone(), claim);
        self.counters.low_fee_claims_recorded =
            self.counters.low_fee_claims_recorded.saturating_add(1);
        self.counters.claimed_rebate_micro_fees = self
            .counters
            .claimed_rebate_micro_fees
            .saturating_add(rebate_micro_fee);
        self.refresh_roots();
        Ok(id)
    }

    pub fn open_disclosure_budget(&mut self, input: DisclosureBudgetInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty("contract_id_commitment", &input.contract_id_commitment)?;
        require_non_empty("receipt_scope_root", &input.receipt_scope_root)?;
        require_non_empty("auditor_commitment", &input.auditor_commitment)?;
        if self.disclosure_budgets.len() >= self.config.max_disclosure_budgets {
            return Err("receipt vault disclosure budget capacity exceeded".to_string());
        }
        if input.budget_units == 0 {
            return Err("disclosure budget must reserve at least one unit".to_string());
        }
        if input.expires_at_height <= self.height {
            return Err("disclosure budget already expired".to_string());
        }
        let id = disclosure_budget_id(
            &input.contract_id_commitment,
            &input.receipt_scope_root,
            &input.auditor_commitment,
            input.budget_nonce,
        );
        let budget = DisclosureBudget {
            id: id.clone(),
            contract_id_commitment: input.contract_id_commitment,
            receipt_scope_root: input.receipt_scope_root,
            auditor_commitment: input.auditor_commitment,
            budget_units: input.budget_units,
            spent_units: 0,
            expires_at_height: input.expires_at_height,
        };
        self.disclosure_budgets.insert(id.clone(), budget);
        self.counters.disclosure_budgets_opened =
            self.counters.disclosure_budgets_opened.saturating_add(1);
        self.counters.disclosure_units_reserved = self
            .counters
            .disclosure_units_reserved
            .saturating_add(input.budget_units);
        self.refresh_roots();
        Ok(id)
    }

    pub fn spend_disclosure_budget(&mut self, input: DisclosureSpendInput) -> Result<()> {
        require_non_empty("budget_id", &input.budget_id)?;
        require_non_empty("receipt_id", &input.receipt_id)?;
        require_non_empty(
            "disclosure_commitment_root",
            &input.disclosure_commitment_root,
        )?;
        if input.units == 0 {
            return Err("disclosure spend must use at least one unit".to_string());
        }
        if !self.receipt_custody.contains_key(&input.receipt_id) {
            return Err("receipt missing for disclosure budget spend".to_string());
        }
        let budget = self
            .disclosure_budgets
            .get_mut(&input.budget_id)
            .ok_or_else(|| "disclosure budget missing".to_string())?;
        if budget.expires_at_height <= self.height {
            return Err("disclosure budget expired".to_string());
        }
        if budget.spent_units.saturating_add(input.units) > budget.budget_units {
            return Err("disclosure budget exceeded".to_string());
        }
        budget.spent_units = budget.spent_units.saturating_add(input.units);
        self.counters.disclosure_units_spent = self
            .counters
            .disclosure_units_spent
            .saturating_add(input.units);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine(&mut self, input: QuarantineInput) -> Result<String> {
        require_non_empty("receipt_id", &input.receipt_id)?;
        require_non_empty("evidence_root", &input.evidence_root)?;
        require_non_empty("challenger_commitment", &input.challenger_commitment)?;
        let receipt = self
            .receipt_custody
            .get_mut(&input.receipt_id)
            .ok_or_else(|| "receipt missing for quarantine".to_string())?;
        if input.release_height <= self.height {
            return Err("quarantine release height must be in the future".to_string());
        }
        receipt.status = CustodyStatus::Quarantined;
        let id = quarantine_id(
            &input.receipt_id,
            input.reason,
            &input.evidence_root,
            &input.challenger_commitment,
        );
        let record = QuarantineRecord {
            id: id.clone(),
            receipt_id: input.receipt_id,
            reason: input.reason,
            evidence_root: input.evidence_root,
            challenger_commitment: input.challenger_commitment,
            release_height: input.release_height,
            resolved: false,
        };
        self.quarantine_records.insert(id.clone(), record);
        self.counters.receipts_quarantined = self.counters.receipts_quarantined.saturating_add(1);
        self.refresh_roots();
        Ok(id)
    }

    pub fn release_from_quarantine(&mut self, quarantine_id: &str) -> Result<()> {
        require_non_empty("quarantine_id", quarantine_id)?;
        let record = self
            .quarantine_records
            .get_mut(quarantine_id)
            .ok_or_else(|| "quarantine record missing".to_string())?;
        if self.height < record.release_height {
            return Err("quarantine release height not reached".to_string());
        }
        let receipt = self
            .receipt_custody
            .get_mut(&record.receipt_id)
            .ok_or_else(|| "quarantined receipt missing".to_string())?;
        receipt.status = CustodyStatus::Released;
        record.resolved = true;
        self.counters.receipts_released = self.counters.receipts_released.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn receipt_commitment_record(&self, receipt_id: &str) -> Result<BTreeMap<String, String>> {
        require_non_empty("receipt_id", receipt_id)?;
        let receipt = self
            .receipt_custody
            .get(receipt_id)
            .ok_or_else(|| "receipt missing for commitment record".to_string())?;
        let mut record = BTreeMap::new();
        record.insert("receipt_id".to_string(), receipt.id.clone());
        record.insert("lane".to_string(), receipt.lane.as_str().to_string());
        record.insert(
            "contract_id_commitment".to_string(),
            receipt.contract_id_commitment.clone(),
        );
        record.insert(
            "caller_commitment".to_string(),
            receipt.caller_commitment.clone(),
        );
        record.insert(
            "receipt_ciphertext_root".to_string(),
            receipt.receipt_ciphertext_root.clone(),
        );
        record.insert(
            "receipt_commitment".to_string(),
            receipt.receipt_commitment.clone(),
        );
        record.insert(
            "storage_commitment_root".to_string(),
            receipt.storage_commitment_root.clone(),
        );
        record.insert(
            "fee_commitment".to_string(),
            fee_commitment(
                receipt.gross_micro_fee,
                receipt.net_micro_fee,
                receipt.rebate_micro_fee,
            ),
        );
        record.insert("status".to_string(), format!("{:?}", receipt.status));
        Ok(record)
    }

    pub fn vault_commitment_record(&self, vault_seal_id: &str) -> Result<BTreeMap<String, String>> {
        require_non_empty("vault_seal_id", vault_seal_id)?;
        let seal = self
            .vault_seals
            .get(vault_seal_id)
            .ok_or_else(|| "vault seal missing for commitment record".to_string())?;
        let mut record = BTreeMap::new();
        record.insert("vault_seal_id".to_string(), seal.id.clone());
        record.insert(
            "receipt_set_root".to_string(),
            string_list_root("RECEIPT-VAULT:COMMITMENT-RECEIPT-SET", &seal.receipt_ids),
        );
        record.insert(
            "vault_operator_commitment".to_string(),
            seal.vault_operator_commitment.clone(),
        );
        record.insert(
            "custody_committee_root".to_string(),
            seal.custody_committee_root.clone(),
        );
        record.insert(
            "storage_commitment_root".to_string(),
            seal.storage_commitment_root.clone(),
        );
        record.insert("sealed_epoch".to_string(), seal.sealed_epoch.to_string());
        record.insert(
            "sealed_at_height".to_string(),
            seal.sealed_at_height.to_string(),
        );
        Ok(record)
    }

    pub fn receipt_has_authorization(&self, receipt_id: &str) -> bool {
        self.contract_authorizations
            .values()
            .any(|authorization| authorization.receipt_id == receipt_id)
    }

    pub fn receipt_has_pq_attestation(&self, receipt_id: &str) -> bool {
        self.contract_attestations
            .values()
            .any(|attestation| attestation.receipt_id == receipt_id)
    }

    pub fn advance_height(&mut self, blocks: u64) {
        self.height = self.height.saturating_add(blocks);
        self.epoch = self.epoch.saturating_add(blocks / 64);
        self.refresh_roots();
    }

    pub fn roots(&self) -> Roots {
        let mut clone = self.clone();
        clone.refresh_roots();
        clone.roots
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots().public_record(),
        }))
    }

    pub fn public_record(&self) -> BTreeMap<String, String> {
        let roots = self.roots();
        let mut record = roots.public_record();
        record.insert(
            "suite".to_string(),
            ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
        );
        record.insert("protocol_version".to_string(), PROTOCOL_VERSION.to_string());
        record.insert("schema_version".to_string(), SCHEMA_VERSION.to_string());
        record.insert("hash_suite".to_string(), HASH_SUITE.to_string());
        record.insert("chain_id".to_string(), self.config.chain_id.clone());
        record.insert("l2_network".to_string(), self.config.l2_network.clone());
        record.insert("fee_asset_id".to_string(), self.config.fee_asset_id.clone());
        record.insert("height".to_string(), self.height.to_string());
        record.insert("epoch".to_string(), self.epoch.to_string());
        record.insert("state_root".to_string(), self.state_root());
        record.insert("roots_only".to_string(), "true".to_string());
        record.insert(
            "sealed_payloads_redacted".to_string(),
            "receipt_ciphertexts_commitments_only".to_string(),
        );
        record
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = payload_root(
            "rebate-receipt-vault-config-root-v1",
            &self.config.public_record(),
        );
        self.roots.counters_root = payload_root(
            "rebate-receipt-vault-counters-root-v1",
            &self.counters.public_record(),
        );
        self.roots.receipt_custody_root = record_root(
            RECEIPT_CUSTODY_SCHEME,
            &self
                .receipt_custody
                .values()
                .map(SealedReceiptCustody::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.storage_commitment_root = record_root(
            STORAGE_COMMITMENT_SCHEME,
            &self
                .receipt_custody
                .values()
                .map(|receipt| {
                    json!({
                        "receipt_id": receipt.id,
                        "storage_commitment_root": receipt.storage_commitment_root,
                    })
                })
                .collect::<Vec<_>>(),
        );
        self.roots.contract_authorization_root = record_root(
            CONTRACT_AUTHORIZATION_SCHEME,
            &self
                .contract_authorizations
                .values()
                .map(ContractAuthorization::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.contract_attestation_root = record_root(
            CONTRACT_ATTESTATION_SCHEME,
            &self
                .contract_attestations
                .values()
                .map(ContractAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.vault_seal_root = record_root(
            VAULT_SEAL_SCHEME,
            &self
                .vault_seals
                .values()
                .map(VaultSeal::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.net_settlement_root = record_root(
            NET_SETTLEMENT_SCHEME,
            &self
                .net_settlements
                .values()
                .map(NetSettlement::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.low_fee_rebate_root = record_root(
            LOW_FEE_REBATE_SCHEME,
            &self
                .low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.low_fee_claim_root = record_root(
            LOW_FEE_CLAIM_SCHEME,
            &self
                .low_fee_claims
                .values()
                .map(LowFeeClaim::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.disclosure_budget_root = record_root(
            DISCLOSURE_BUDGET_SCHEME,
            &self
                .disclosure_budgets
                .values()
                .map(DisclosureBudget::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.quarantine_root = record_root(
            QUARANTINE_SCHEME,
            &self
                .quarantine_records
                .values()
                .map(QuarantineRecord::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = string_set_root(NULLIFIER_SCHEME, &self.replay_nullifiers);
        self.roots.policy_root = self.policy_root();
        self.roots.public_record_root = payload_root(
            PUBLIC_RECORD_ROOT_SCHEME,
            &json!(self.public_record_without_state_root()),
        );
    }

    fn public_record_without_state_root(&self) -> BTreeMap<String, String> {
        let mut record = self.roots.public_record();
        record.insert(
            "suite".to_string(),
            ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
        );
        record.insert("protocol_version".to_string(), PROTOCOL_VERSION.to_string());
        record.insert("height".to_string(), self.height.to_string());
        record.insert("epoch".to_string(), self.epoch.to_string());
        record
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> BTreeMap<String, String> {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn sealed_receipt_id(
    lane: VaultLane,
    contract_id_commitment: &str,
    receipt_commitment: &str,
    replay_nullifier: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:SEALED-RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(contract_id_commitment),
            HashPart::Str(receipt_commitment),
            HashPart::Str(replay_nullifier),
            HashPart::U64(nonce),
        ],
    )
}

pub fn contract_authorization_id(
    receipt_id: &str,
    contract_id_commitment: &str,
    authorized_method_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:AUTHORIZATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(contract_id_commitment),
            HashPart::Str(authorized_method_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn contract_attestation_id(
    receipt_id: &str,
    contract_id_commitment: &str,
    pq_signature_commitment: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(contract_id_commitment),
            HashPart::Str(pq_signature_commitment),
            HashPart::U64(nonce),
        ],
    )
}

pub fn vault_seal_id(
    receipt_ids: &[String],
    vault_operator_commitment: &str,
    custody_committee_root: &str,
    nonce: u64,
) -> String {
    let receipt_set_root = string_list_root("RECEIPT-VAULT:SEAL-ID-RECEIPTS", receipt_ids);
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:SEAL-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&receipt_set_root),
            HashPart::Str(vault_operator_commitment),
            HashPart::Str(custody_committee_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn net_settlement_id(
    vault_seal_id: &str,
    netting_commitment_root: &str,
    fee_liability_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:NET-SETTLEMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(vault_seal_id),
            HashPart::Str(netting_commitment_root),
            HashPart::Str(fee_liability_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn rebate_id(
    settlement_id: &str,
    receipt_id: &str,
    rebate_recipient_commitment: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:REBATE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(settlement_id),
            HashPart::Str(receipt_id),
            HashPart::Str(rebate_recipient_commitment),
            HashPart::U64(nonce),
        ],
    )
}

pub fn low_fee_claim_id(
    rebate_id: &str,
    claim_commitment: &str,
    claim_nullifier: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT-REBATE:LOW-FEE-CLAIM-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(rebate_id),
            HashPart::Str(claim_commitment),
            HashPart::Str(claim_nullifier),
            HashPart::U64(nonce),
        ],
    )
}

pub fn disclosure_budget_id(
    contract_id_commitment: &str,
    receipt_scope_root: &str,
    auditor_commitment: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:DISCLOSURE-BUDGET-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(contract_id_commitment),
            HashPart::Str(receipt_scope_root),
            HashPart::Str(auditor_commitment),
            HashPart::U64(nonce),
        ],
    )
}

pub fn quarantine_id(
    receipt_id: &str,
    reason: QuarantineReason,
    evidence_root: &str,
    challenger_commitment: &str,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:QUARANTINE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(challenger_commitment),
        ],
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-RECEIPT-VAULT:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    if records.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(domain, records)
    }
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    payload_root(domain, &json!({ "empty": true }))
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn string_list_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .enumerate()
        .map(|(index, value)| json!({ "index": index, "value": value }))
        .collect::<Vec<_>>();
    record_root(domain, &records)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    record_root(domain, &records)
}

fn fee_commitment(gross_micro_fee: u64, net_micro_fee: u64, rebate_micro_fee: u64) -> String {
    payload_root(
        "RECEIPT-VAULT:FEE-COMMITMENT",
        &json!({
            "gross_micro_fee": gross_micro_fee,
            "net_micro_fee": net_micro_fee,
            "rebate_micro_fee": rebate_micro_fee,
        }),
    )
}

fn bps(value: u64, bps: u64) -> u64 {
    ((value as u128).saturating_mul(bps as u128) / (MAX_BPS as u128)) as u64
}

fn proportional_share(value: u64, total: u64, allocation: u64) -> u64 {
    if total == 0 {
        0
    } else {
        ((value as u128).saturating_mul(allocation as u128) / (total as u128)) as u64
    }
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} is required"))
    } else {
        Ok(())
    }
}
