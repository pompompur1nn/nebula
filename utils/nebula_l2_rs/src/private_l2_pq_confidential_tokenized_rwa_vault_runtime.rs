use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-rwa-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_SCHEMA_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const HASH_SUITE: &str = PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_HASH_SUITE;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-tokenized-rwa-vault-v1";
pub const PQ_AUTH_SUITE: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_PQ_AUTH_SUITE;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_PRIVACY_SCHEME: &str =
    "monero-viewtag-stealth-address-nullifier-fence-confidential-rwa-v1";
pub const PRIVACY_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_PRIVACY_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_CONTRACT_SCHEME: &str =
    "pq-private-smart-contract-rwa-vault-covenant-v1";
pub const CONTRACT_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_CONTRACT_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_ORACLE_SCHEME: &str =
    "pq-threshold-oracle-proof-of-reserve-attestation-v1";
pub const ORACLE_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_ORACLE_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_LOW_FEE_SCHEME: &str =
    "recursive-proof-batched-low-fee-rwa-redemption-v1";
pub const LOW_FEE_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_VAULT_RUNTIME_LOW_FEE_SCHEME;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_640_000;
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "asset:xmr-rwa-settlement-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RECORD_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REDEMPTION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_PROOF_REFRESH_BLOCKS: u64 = 720;
pub const DEFAULT_ORACLE_QUORUM: u16 = 7;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 15;
pub const DEFAULT_MAX_PROTOCOL_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_250;
pub const DEFAULT_SLASHING_ESCROW_BPS: u64 = 500;
pub const DEFAULT_MAX_SHARE_CLASSES_PER_VAULT: usize = 12;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VAULTS: usize = 262_144;
pub const MAX_SHARE_CLASSES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_REDEMPTIONS: usize = 4_194_304;
pub const MAX_FENCES: usize = 8_388_608;
pub const MAX_SNAPSHOTS: usize = 2_097_152;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_ORACLES: usize = 2_097_152;
pub const MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const MAX_SLASHING_EVIDENCE: usize = 2_097_152;
pub const MAX_RESERVE_ATTESTATIONS: usize = MAX_ATTESTATIONS;
pub const MAX_REDEMPTION_QUEUE: usize = MAX_REDEMPTIONS;
pub const MAX_COMPLIANCE_FENCES: usize = MAX_FENCES;
pub const MAX_YIELD_SNAPSHOTS: usize = MAX_SNAPSHOTS;
pub const MAX_FEE_REBATES: usize = MAX_REBATES;
pub const MAX_ORACLE_ATTESTATIONS: usize = MAX_ORACLES;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaAssetKind {
    TreasuryBill,
    MoneyMarketFund,
    PrivateCredit,
    RealEstateDebt,
    CommodityReceipt,
    CarbonCredit,
    InvoiceReceivable,
    TokenizedEquity,
}

impl RwaAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TreasuryBill => "treasury_bill",
            Self::MoneyMarketFund => "money_market_fund",
            Self::PrivateCredit => "private_credit",
            Self::RealEstateDebt => "real_estate_debt",
            Self::CommodityReceipt => "commodity_receipt",
            Self::CarbonCredit => "carbon_credit",
            Self::InvoiceReceivable => "invoice_receivable",
            Self::TokenizedEquity => "tokenized_equity",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    DepositOnly,
    RedemptionOnly,
    ProofRefreshOnly,
    Paused,
    Frozen,
    Slashing,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::RedemptionOnly => "redemption_only",
            Self::ProofRefreshOnly => "proof_refresh_only",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Slashing => "slashing",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }

    pub fn accepts_redemptions(self) -> bool {
        matches!(self, Self::Active | Self::RedemptionOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareClassSeniority {
    Senior,
    Mezzanine,
    Junior,
    Sponsor,
    LiquidityProvider,
}

impl ShareClassSeniority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::Sponsor => "sponsor",
            Self::LiquidityProvider => "liquidity_provider",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Queued,
    Batched,
    OraclePriced,
    ReserveLocked,
    SettlementReady,
    Settled,
    Cancelled,
    Challenged,
}

impl QueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Batched => "batched",
            Self::OraclePriced => "oracle_priced",
            Self::ReserveLocked => "reserve_locked",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ReserveShortfall,
    OracleEquivocation,
    ComplianceBypass,
    PrivacyLeak,
    UnauthorizedMint,
    RedemptionCensorship,
    YieldMisstatement,
    PqSignatureFault,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveShortfall => "reserve_shortfall",
            Self::OracleEquivocation => "oracle_equivocation",
            Self::ComplianceBypass => "compliance_bypass",
            Self::PrivacyLeak => "privacy_leak",
            Self::UnauthorizedMint => "unauthorized_mint",
            Self::RedemptionCensorship => "redemption_censorship",
            Self::YieldMisstatement => "yield_misstatement",
            Self::PqSignatureFault => "pq_signature_fault",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub record_ttl_blocks: u64,
    pub redemption_ttl_blocks: u64,
    pub proof_refresh_blocks: u64,
    pub oracle_quorum: u16,
    pub max_user_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub slashing_escrow_bps: u64,
    pub max_share_classes_per_vault: usize,
    pub enabled_contracts_root: String,
    pub enabled_oracle_root: String,
    pub pq_policy_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            record_ttl_blocks: DEFAULT_RECORD_TTL_BLOCKS,
            redemption_ttl_blocks: DEFAULT_REDEMPTION_TTL_BLOCKS,
            proof_refresh_blocks: DEFAULT_PROOF_REFRESH_BLOCKS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_protocol_fee_bps: DEFAULT_MAX_PROTOCOL_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            slashing_escrow_bps: DEFAULT_SLASHING_ESCROW_BPS,
            max_share_classes_per_vault: DEFAULT_MAX_SHARE_CLASSES_PER_VAULT,
            enabled_contracts_root: empty_root("PRIVATE-L2-PQ-RWA-ENABLED-CONTRACTS"),
            enabled_oracle_root: empty_root("PRIVATE-L2-PQ-RWA-ENABLED-ORACLES"),
            pq_policy_root: deterministic_label("PRIVATE-L2-PQ-RWA-POLICY", "devnet", 0),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "record_ttl_blocks": self.record_ttl_blocks,
            "redemption_ttl_blocks": self.redemption_ttl_blocks,
            "proof_refresh_blocks": self.proof_refresh_blocks,
            "oracle_quorum": self.oracle_quorum,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_protocol_fee_bps": self.max_protocol_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "slashing_escrow_bps": self.slashing_escrow_bps,
            "max_share_classes_per_vault": self.max_share_classes_per_vault,
            "enabled_contracts_root": self.enabled_contracts_root,
            "enabled_oracle_root": self.enabled_oracle_root,
            "pq_policy_root": self.pq_policy_root,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "unexpected schema version",
        )?;
        ensure(
            self.min_pq_security_bits >= 256,
            "pq security below 256 bits",
        )?;
        ensure(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        ensure(
            self.target_privacy_set_size <= self.batch_privacy_set_size,
            "batch privacy below target",
        )?;
        ensure(self.max_user_fee_bps <= MAX_BPS, "user fee bps overflow")?;
        ensure(
            self.max_protocol_fee_bps <= MAX_BPS,
            "protocol fee bps overflow",
        )?;
        ensure(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate exceeds user fee cap",
        )?;
        ensure(self.oracle_quorum > 0, "oracle quorum is zero")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub share_classes: u64,
    pub reserve_attestations: u64,
    pub redemption_queue: u64,
    pub compliance_fences: u64,
    pub yield_snapshots: u64,
    pub fee_rebates: u64,
    pub oracle_attestations: u64,
    pub privacy_fences: u64,
    pub slashing_evidence: u64,
    pub state_transitions: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            vaults: 0,
            share_classes: 0,
            reserve_attestations: 0,
            redemption_queue: 0,
            compliance_fences: 0,
            yield_snapshots: 0,
            fee_rebates: 0,
            oracle_attestations: 0,
            privacy_fences: 0,
            slashing_evidence: 0,
            state_transitions: 0,
            public_records: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vaults": self.vaults,
            "share_classes": self.share_classes,
            "reserve_attestations": self.reserve_attestations,
            "redemption_queue": self.redemption_queue,
            "compliance_fences": self.compliance_fences,
            "yield_snapshots": self.yield_snapshots,
            "fee_rebates": self.fee_rebates,
            "oracle_attestations": self.oracle_attestations,
            "privacy_fences": self.privacy_fences,
            "slashing_evidence": self.slashing_evidence,
            "state_transitions": self.state_transitions,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub vaults_root: String,
    pub share_classes_root: String,
    pub reserve_attestations_root: String,
    pub redemption_queue_root: String,
    pub compliance_fences_root: String,
    pub yield_snapshots_root: String,
    pub fee_rebates_root: String,
    pub oracle_attestations_root: String,
    pub privacy_fences_root: String,
    pub slashing_evidence_root: String,
    pub live_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "vaults_root": self.vaults_root,
            "share_classes_root": self.share_classes_root,
            "reserve_attestations_root": self.reserve_attestations_root,
            "redemption_queue_root": self.redemption_queue_root,
            "compliance_fences_root": self.compliance_fences_root,
            "yield_snapshots_root": self.yield_snapshots_root,
            "fee_rebates_root": self.fee_rebates_root,
            "oracle_attestations_root": self.oracle_attestations_root,
            "privacy_fences_root": self.privacy_fences_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "live_nullifier_root": self.live_nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialRwaVault {
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl ConfidentialRwaVault {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-VAULT-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-VAULT-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-VAULT-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-VAULT-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-VAULT-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-VAULT-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.vault_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-VAULT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential RWA vault registry entry",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "vault_id": self.vault_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("PRIVATE-L2-PQ-RWA-VAULT-RECORD", &self.public_record())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenizedShareClass {
    pub share_class_id: String,
    pub vault_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl TokenizedShareClass {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SHARE-CLASS-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SHARE-CLASS-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SHARE-CLASS-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SHARE-CLASS-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SHARE-CLASS-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-SHARE-CLASS-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.share_class_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-SHARE-CLASS-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "tokenized share class",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "share_class_id": self.share_class_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-RWA-SHARE-CLASS-RECORD",
            &self.public_record(),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofOfReserveAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl ProofOfReserveAttestation {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            attestation_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.attestation_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof-of-reserve attestation",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATION-RECORD",
            &self.public_record(),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionQueueEntry {
    pub redemption_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl RedemptionQueueEntry {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            redemption_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-REDEMPTION-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-REDEMPTION-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-REDEMPTION-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-REDEMPTION-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-REDEMPTION-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-REDEMPTION-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.redemption_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-REDEMPTION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "redemption queue entry",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "redemption_id": self.redemption_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("PRIVATE-L2-PQ-RWA-REDEMPTION-RECORD", &self.public_record())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceNullifierFence {
    pub fence_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl ComplianceNullifierFence {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            fence_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.fence_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance nullifier fence",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "fence_id": self.fence_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCE-RECORD",
            &self.public_record(),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct YieldSnapshot {
    pub snapshot_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl YieldSnapshot {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            snapshot_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.snapshot_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "yield snapshot",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "snapshot_id": self.snapshot_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOT-RECORD",
            &self.public_record(),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl FeeRebate {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            rebate_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-FEE-REBATE-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-FEE-REBATE-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-FEE-REBATE-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-FEE-REBATE-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-FEE-REBATE-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.rebate_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-FEE-REBATE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee rebate",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "rebate_id": self.rebate_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("PRIVATE-L2-PQ-RWA-FEE-REBATE-RECORD", &self.public_record())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestation {
    pub oracle_attestation_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl OracleAttestation {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            oracle_attestation_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.oracle_attestation_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle attestation",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "oracle_attestation_id": self.oracle_attestation_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATION-RECORD",
            &self.public_record(),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub privacy_fence_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl PrivacyFence {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            privacy_fence_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.privacy_fence_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy fence",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "privacy_fence_id": self.privacy_fence_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-RWA-PRIVACY-FENCE-RECORD",
            &self.public_record(),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub operator_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub value_commitment: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub oracle_root: String,
    pub compliance_root: String,
    pub privacy_root: String,
    pub contract_root: String,
    pub pq_signature_root: String,
    pub nullifier_hash: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl SlashingEvidence {
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let mut record = Self {
            evidence_id: String::new(),
            vault_id,
            share_class_id,
            owner_commitment,
            operator_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-OPERATOR",
                "operator",
                sequence,
            ),
            asset_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-ASSET",
                "asset",
                sequence,
            ),
            amount_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-AMOUNT",
                "amount",
                sequence,
            ),
            value_commitment: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-VALUE",
                "value",
                sequence,
            ),
            reserve_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-RESERVE"),
            liability_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-LIABILITY"),
            oracle_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-ORACLE"),
            compliance_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-COMPLIANCE"),
            privacy_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-PRIVACY"),
            contract_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-CONTRACT"),
            pq_signature_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-PQ-SIGNATURE"),
            nullifier_hash: deterministic_label(
                "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-NULLIFIER",
                "nullifier",
                sequence,
            ),
            metadata_root: empty_root("PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-METADATA"),
            opened_at_height: DEVNET_HEIGHT + sequence,
            expires_at_height: DEVNET_HEIGHT + sequence + DEFAULT_RECORD_TTL_BLOCKS,
            sequence,
        };
        record.evidence_id = record.deterministic_id();
        record
    }

    pub fn deterministic_id(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.vault_id),
                HashPart::Str(&self.share_class_id),
                HashPart::Str(&self.owner_commitment),
                HashPart::Str(&self.nullifier_hash),
                HashPart::Int(self.sequence as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing evidence",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "value_commitment": self.value_commitment,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "oracle_root": self.oracle_root,
            "compliance_root": self.compliance_root,
            "privacy_root": self.privacy_root,
            "contract_root": self.contract_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_hash": self.nullifier_hash,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE-RECORD",
            &self.public_record(),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub vaults: BTreeMap<String, ConfidentialRwaVault>,
    pub share_classes: BTreeMap<String, TokenizedShareClass>,
    pub reserve_attestations: BTreeMap<String, ProofOfReserveAttestation>,
    pub redemption_queue: BTreeMap<String, RedemptionQueueEntry>,
    pub compliance_fences: BTreeMap<String, ComplianceNullifierFence>,
    pub yield_snapshots: BTreeMap<String, YieldSnapshot>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::new(),
            vaults: BTreeMap::new(),
            share_classes: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            redemption_queue: BTreeMap::new(),
            compliance_fences: BTreeMap::new(),
            yield_snapshots: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.seed_devnet_records();
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root("PRIVATE-L2-PQ-RWA-CONFIG", &self.config.public_record()),
            counters_root: payload_root(
                "PRIVATE-L2-PQ-RWA-COUNTERS",
                &self.counters.public_record(),
            ),
            vaults_root: map_root("PRIVATE-L2-PQ-RWA-VAULTS", &self.vaults),
            share_classes_root: map_root("PRIVATE-L2-PQ-RWA-SHARE-CLASSES", &self.share_classes),
            reserve_attestations_root: map_root(
                "PRIVATE-L2-PQ-RWA-RESERVE-ATTESTATIONS",
                &self.reserve_attestations,
            ),
            redemption_queue_root: map_root(
                "PRIVATE-L2-PQ-RWA-REDEMPTION-QUEUE",
                &self.redemption_queue,
            ),
            compliance_fences_root: map_root(
                "PRIVATE-L2-PQ-RWA-COMPLIANCE-FENCES",
                &self.compliance_fences,
            ),
            yield_snapshots_root: map_root(
                "PRIVATE-L2-PQ-RWA-YIELD-SNAPSHOTS",
                &self.yield_snapshots,
            ),
            fee_rebates_root: map_root("PRIVATE-L2-PQ-RWA-FEE-REBATES", &self.fee_rebates),
            oracle_attestations_root: map_root(
                "PRIVATE-L2-PQ-RWA-ORACLE-ATTESTATIONS",
                &self.oracle_attestations,
            ),
            privacy_fences_root: map_root("PRIVATE-L2-PQ-RWA-PRIVACY-FENCES", &self.privacy_fences),
            slashing_evidence_root: map_root(
                "PRIVATE-L2-PQ-RWA-SLASHING-EVIDENCE",
                &self.slashing_evidence,
            ),
            live_nullifier_root: set_root(
                "PRIVATE-L2-PQ-RWA-LIVE-NULLIFIERS",
                &self.spent_nullifiers,
            ),
            public_record_root: map_value_root(
                "PRIVATE-L2-PQ-RWA-PUBLIC-RECORDS",
                &self.public_records,
            ),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_tokenized_rwa_vault_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "privacy_scheme": PRIVACY_SCHEME,
            "contract_scheme": CONTRACT_SCHEME,
            "oracle_scheme": ORACLE_SCHEME,
            "low_fee_scheme": LOW_FEE_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "vaults_count": self.vaults.len() as u64,
            "share_classes_count": self.share_classes.len() as u64,
            "reserve_attestations_count": self.reserve_attestations.len() as u64,
            "redemption_queue_count": self.redemption_queue.len() as u64,
            "compliance_fences_count": self.compliance_fences.len() as u64,
            "yield_snapshots_count": self.yield_snapshots.len() as u64,
            "fee_rebates_count": self.fee_rebates.len() as u64,
            "oracle_attestations_count": self.oracle_attestations.len() as u64,
            "privacy_fences_count": self.privacy_fences.len() as u64,
            "slashing_evidence_count": self.slashing_evidence.len() as u64,
            "spent_nullifier_count": self.spent_nullifiers.len() as u64,
            "public_record_count": self.public_records.len() as u64,
        })
    }

    pub fn insert_vault(&mut self, mut record: ConfidentialRwaVault) -> Result<String> {
        ensure(self.vaults.len() < MAX_VAULTS, "vaults capacity exhausted")?;
        let expected_id = record.deterministic_id();
        if record.vault_id.is_empty() {
            record.vault_id = expected_id.clone();
        }
        ensure(record.vault_id == expected_id, "vaults id mismatch")?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.vault_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.vaults.insert(record_id.clone(), record);
        self.counters.vaults = self.vaults.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn vault(&self, record_id: &str) -> Option<&ConfidentialRwaVault> {
        self.vaults.get(record_id)
    }

    pub fn insert_share_classe(&mut self, mut record: TokenizedShareClass) -> Result<String> {
        ensure(
            self.share_classes.len() < MAX_SHARE_CLASSES,
            "share_classes capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.share_class_id.is_empty() {
            record.share_class_id = expected_id.clone();
        }
        ensure(
            record.share_class_id == expected_id,
            "share_classes id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.share_class_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.share_classes.insert(record_id.clone(), record);
        self.counters.share_classes = self.share_classes.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn share_classe(&self, record_id: &str) -> Option<&TokenizedShareClass> {
        self.share_classes.get(record_id)
    }

    pub fn insert_reserve_attestation(
        &mut self,
        mut record: ProofOfReserveAttestation,
    ) -> Result<String> {
        ensure(
            self.reserve_attestations.len() < MAX_RESERVE_ATTESTATIONS,
            "reserve_attestations capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.attestation_id.is_empty() {
            record.attestation_id = expected_id.clone();
        }
        ensure(
            record.attestation_id == expected_id,
            "reserve_attestations id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.attestation_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.reserve_attestations.insert(record_id.clone(), record);
        self.counters.reserve_attestations = self.reserve_attestations.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn reserve_attestation(&self, record_id: &str) -> Option<&ProofOfReserveAttestation> {
        self.reserve_attestations.get(record_id)
    }

    pub fn insert_redemption_queu(&mut self, mut record: RedemptionQueueEntry) -> Result<String> {
        ensure(
            self.redemption_queue.len() < MAX_REDEMPTION_QUEUE,
            "redemption_queue capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.redemption_id.is_empty() {
            record.redemption_id = expected_id.clone();
        }
        ensure(
            record.redemption_id == expected_id,
            "redemption_queue id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.redemption_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.redemption_queue.insert(record_id.clone(), record);
        self.counters.redemption_queue = self.redemption_queue.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn redemption_queu(&self, record_id: &str) -> Option<&RedemptionQueueEntry> {
        self.redemption_queue.get(record_id)
    }

    pub fn insert_compliance_fence(
        &mut self,
        mut record: ComplianceNullifierFence,
    ) -> Result<String> {
        ensure(
            self.compliance_fences.len() < MAX_COMPLIANCE_FENCES,
            "compliance_fences capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.fence_id.is_empty() {
            record.fence_id = expected_id.clone();
        }
        ensure(
            record.fence_id == expected_id,
            "compliance_fences id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.fence_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.compliance_fences.insert(record_id.clone(), record);
        self.counters.compliance_fences = self.compliance_fences.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn compliance_fence(&self, record_id: &str) -> Option<&ComplianceNullifierFence> {
        self.compliance_fences.get(record_id)
    }

    pub fn insert_yield_snapshot(&mut self, mut record: YieldSnapshot) -> Result<String> {
        ensure(
            self.yield_snapshots.len() < MAX_YIELD_SNAPSHOTS,
            "yield_snapshots capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.snapshot_id.is_empty() {
            record.snapshot_id = expected_id.clone();
        }
        ensure(
            record.snapshot_id == expected_id,
            "yield_snapshots id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.snapshot_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.yield_snapshots.insert(record_id.clone(), record);
        self.counters.yield_snapshots = self.yield_snapshots.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn yield_snapshot(&self, record_id: &str) -> Option<&YieldSnapshot> {
        self.yield_snapshots.get(record_id)
    }

    pub fn insert_fee_rebate(&mut self, mut record: FeeRebate) -> Result<String> {
        ensure(
            self.fee_rebates.len() < MAX_FEE_REBATES,
            "fee_rebates capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.rebate_id.is_empty() {
            record.rebate_id = expected_id.clone();
        }
        ensure(record.rebate_id == expected_id, "fee_rebates id mismatch")?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.rebate_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.fee_rebates.insert(record_id.clone(), record);
        self.counters.fee_rebates = self.fee_rebates.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn fee_rebate(&self, record_id: &str) -> Option<&FeeRebate> {
        self.fee_rebates.get(record_id)
    }

    pub fn insert_oracle_attestation(&mut self, mut record: OracleAttestation) -> Result<String> {
        ensure(
            self.oracle_attestations.len() < MAX_ORACLE_ATTESTATIONS,
            "oracle_attestations capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.oracle_attestation_id.is_empty() {
            record.oracle_attestation_id = expected_id.clone();
        }
        ensure(
            record.oracle_attestation_id == expected_id,
            "oracle_attestations id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.oracle_attestation_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.oracle_attestations.insert(record_id.clone(), record);
        self.counters.oracle_attestations = self.oracle_attestations.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn oracle_attestation(&self, record_id: &str) -> Option<&OracleAttestation> {
        self.oracle_attestations.get(record_id)
    }

    pub fn insert_privacy_fence(&mut self, mut record: PrivacyFence) -> Result<String> {
        ensure(
            self.privacy_fences.len() < MAX_PRIVACY_FENCES,
            "privacy_fences capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.privacy_fence_id.is_empty() {
            record.privacy_fence_id = expected_id.clone();
        }
        ensure(
            record.privacy_fence_id == expected_id,
            "privacy_fences id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.privacy_fence_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.privacy_fences.insert(record_id.clone(), record);
        self.counters.privacy_fences = self.privacy_fences.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn privacy_fence(&self, record_id: &str) -> Option<&PrivacyFence> {
        self.privacy_fences.get(record_id)
    }

    pub fn insert_slashing_evidenc(&mut self, mut record: SlashingEvidence) -> Result<String> {
        ensure(
            self.slashing_evidence.len() < MAX_SLASHING_EVIDENCE,
            "slashing_evidence capacity exhausted",
        )?;
        let expected_id = record.deterministic_id();
        if record.evidence_id.is_empty() {
            record.evidence_id = expected_id.clone();
        }
        ensure(
            record.evidence_id == expected_id,
            "slashing_evidence id mismatch",
        )?;
        ensure(
            self.spent_nullifiers.insert(record.nullifier_hash.clone()),
            "duplicate nullifier",
        )?;
        let record_id = record.evidence_id.clone();
        self.public_records
            .insert(record_id.clone(), record.public_record());
        self.slashing_evidence.insert(record_id.clone(), record);
        self.counters.slashing_evidence = self.slashing_evidence.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        Ok(record_id)
    }

    pub fn slashing_evidenc(&self, record_id: &str) -> Option<&SlashingEvidence> {
        self.slashing_evidence.get(record_id)
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload: Value,
        emitted_at_height: u64,
    ) -> String {
        let payload_root = payload_root("PRIVATE-L2-PQ-RWA-PUBLIC-PAYLOAD", &payload);
        let record_id = public_record_id(record_kind, subject_id, &payload_root, emitted_at_height);
        self.public_records.insert(
            record_id.clone(),
            json!({
                "record_id": record_id,
                "record_kind": record_kind,
                "subject_id": subject_id,
                "payload_root": payload_root,
                "payload": payload,
                "emitted_at_height": emitted_at_height,
            }),
        );
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        record_id
    }

    fn seed_devnet_records(&mut self) {
        let vaults_record = ConfidentialRwaVault::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "vaults", 1),
            1,
        );
        let _ = self.insert_vault(vaults_record);
        let share_classes_record = TokenizedShareClass::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "share_classes", 2),
            2,
        );
        let _ = self.insert_share_classe(share_classes_record);
        let reserve_attestations_record = ProofOfReserveAttestation::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "reserve_attestations", 3),
            3,
        );
        let _ = self.insert_reserve_attestation(reserve_attestations_record);
        let redemption_queue_record = RedemptionQueueEntry::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "redemption_queue", 4),
            4,
        );
        let _ = self.insert_redemption_queu(redemption_queue_record);
        let compliance_fences_record = ComplianceNullifierFence::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "compliance_fences", 5),
            5,
        );
        let _ = self.insert_compliance_fence(compliance_fences_record);
        let yield_snapshots_record = YieldSnapshot::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "yield_snapshots", 6),
            6,
        );
        let _ = self.insert_yield_snapshot(yield_snapshots_record);
        let fee_rebates_record = FeeRebate::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "fee_rebates", 7),
            7,
        );
        let _ = self.insert_fee_rebate(fee_rebates_record);
        let oracle_attestations_record = OracleAttestation::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "oracle_attestations", 8),
            8,
        );
        let _ = self.insert_oracle_attestation(oracle_attestations_record);
        let privacy_fences_record = PrivacyFence::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "privacy_fences", 9),
            9,
        );
        let _ = self.insert_privacy_fence(privacy_fences_record);
        let slashing_evidence_record = SlashingEvidence::new(
            "devnet-rwa-vault",
            "devnet-senior-share",
            deterministic_label("PRIVATE-L2-PQ-RWA-OWNER", "slashing_evidence", 10),
            10,
        );
        let _ = self.insert_slashing_evidenc(slashing_evidence_record);
        let snapshot = self.public_record_without_root();
        self.publish_public_record(
            "devnet_state_snapshot",
            "devnet-rwa-vault",
            snapshot,
            DEVNET_HEIGHT,
        );
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-RWA-VAULT-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-RWA-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
        ],
        32,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn deterministic_label(domain: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn map_root<T>(domain: &str, records: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = records
        .iter()
        .map(
            |(record_id, record)| json!({"record_id": record_id, "record": record.public_record()}),
        )
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_value_root(domain: &str, records: &BTreeMap<String, Value>) -> String {
    let leaves = records
        .iter()
        .map(|(record_id, record)| json!({"record_id": record_id, "record": record}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for ConfidentialRwaVault {
    fn public_record(&self) -> Value {
        ConfidentialRwaVault::public_record(self)
    }
}

impl PublicRecord for TokenizedShareClass {
    fn public_record(&self) -> Value {
        TokenizedShareClass::public_record(self)
    }
}

impl PublicRecord for ProofOfReserveAttestation {
    fn public_record(&self) -> Value {
        ProofOfReserveAttestation::public_record(self)
    }
}

impl PublicRecord for RedemptionQueueEntry {
    fn public_record(&self) -> Value {
        RedemptionQueueEntry::public_record(self)
    }
}

impl PublicRecord for ComplianceNullifierFence {
    fn public_record(&self) -> Value {
        ComplianceNullifierFence::public_record(self)
    }
}

impl PublicRecord for YieldSnapshot {
    fn public_record(&self) -> Value {
        YieldSnapshot::public_record(self)
    }
}

impl PublicRecord for FeeRebate {
    fn public_record(&self) -> Value {
        FeeRebate::public_record(self)
    }
}

impl PublicRecord for OracleAttestation {
    fn public_record(&self) -> Value {
        OracleAttestation::public_record(self)
    }
}

impl PublicRecord for PrivacyFence {
    fn public_record(&self) -> Value {
        PrivacyFence::public_record(self)
    }
}

impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

pub const RWA_VAULT_CONTROL_DOMAIN_000: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-000";
pub fn rwa_vault_control_root_000(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_000,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_001: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-001";
pub fn rwa_vault_control_root_001(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_001,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_002: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-002";
pub fn rwa_vault_control_root_002(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_002,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_003: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-003";
pub fn rwa_vault_control_root_003(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_003,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_004: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-004";
pub fn rwa_vault_control_root_004(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_004,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_005: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-005";
pub fn rwa_vault_control_root_005(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_005,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_006: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-006";
pub fn rwa_vault_control_root_006(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_006,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_007: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-007";
pub fn rwa_vault_control_root_007(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_007,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_008: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-008";
pub fn rwa_vault_control_root_008(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_008,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_009: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-009";
pub fn rwa_vault_control_root_009(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_009,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_010: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-010";
pub fn rwa_vault_control_root_010(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_010,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_011: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-011";
pub fn rwa_vault_control_root_011(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_011,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_012: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-012";
pub fn rwa_vault_control_root_012(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_012,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_013: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-013";
pub fn rwa_vault_control_root_013(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_013,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_014: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-014";
pub fn rwa_vault_control_root_014(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_014,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_015: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-015";
pub fn rwa_vault_control_root_015(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_015,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_016: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-016";
pub fn rwa_vault_control_root_016(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_016,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_017: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-017";
pub fn rwa_vault_control_root_017(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_017,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_018: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-018";
pub fn rwa_vault_control_root_018(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_018,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_019: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-019";
pub fn rwa_vault_control_root_019(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_019,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_020: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-020";
pub fn rwa_vault_control_root_020(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_020,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_021: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-021";
pub fn rwa_vault_control_root_021(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_021,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_022: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-022";
pub fn rwa_vault_control_root_022(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_022,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_023: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-023";
pub fn rwa_vault_control_root_023(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_023,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_024: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-024";
pub fn rwa_vault_control_root_024(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_024,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_025: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-025";
pub fn rwa_vault_control_root_025(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_025,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_026: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-026";
pub fn rwa_vault_control_root_026(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_026,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_027: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-027";
pub fn rwa_vault_control_root_027(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_027,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_028: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-028";
pub fn rwa_vault_control_root_028(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_028,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_029: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-029";
pub fn rwa_vault_control_root_029(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_029,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_030: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-030";
pub fn rwa_vault_control_root_030(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_030,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_031: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-031";
pub fn rwa_vault_control_root_031(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_031,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_032: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-032";
pub fn rwa_vault_control_root_032(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_032,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_033: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-033";
pub fn rwa_vault_control_root_033(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_033,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_034: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-034";
pub fn rwa_vault_control_root_034(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_034,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_035: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-035";
pub fn rwa_vault_control_root_035(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_035,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_036: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-036";
pub fn rwa_vault_control_root_036(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_036,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_037: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-037";
pub fn rwa_vault_control_root_037(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_037,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_038: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-038";
pub fn rwa_vault_control_root_038(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_038,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_039: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-039";
pub fn rwa_vault_control_root_039(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_039,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_040: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-040";
pub fn rwa_vault_control_root_040(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_040,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_041: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-041";
pub fn rwa_vault_control_root_041(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_041,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_042: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-042";
pub fn rwa_vault_control_root_042(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_042,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_043: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-043";
pub fn rwa_vault_control_root_043(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_043,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_044: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-044";
pub fn rwa_vault_control_root_044(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_044,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_045: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-045";
pub fn rwa_vault_control_root_045(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_045,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_046: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-046";
pub fn rwa_vault_control_root_046(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_046,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_047: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-047";
pub fn rwa_vault_control_root_047(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_047,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_048: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-048";
pub fn rwa_vault_control_root_048(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_048,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_049: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-049";
pub fn rwa_vault_control_root_049(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_049,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_050: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-050";
pub fn rwa_vault_control_root_050(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_050,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_051: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-051";
pub fn rwa_vault_control_root_051(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_051,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_052: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-052";
pub fn rwa_vault_control_root_052(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_052,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_053: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-053";
pub fn rwa_vault_control_root_053(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_053,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_054: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-054";
pub fn rwa_vault_control_root_054(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_054,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_055: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-055";
pub fn rwa_vault_control_root_055(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_055,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_056: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-056";
pub fn rwa_vault_control_root_056(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_056,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_057: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-057";
pub fn rwa_vault_control_root_057(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_057,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_058: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-058";
pub fn rwa_vault_control_root_058(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_058,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_059: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-059";
pub fn rwa_vault_control_root_059(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_059,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_060: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-060";
pub fn rwa_vault_control_root_060(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_060,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_061: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-061";
pub fn rwa_vault_control_root_061(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_061,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_062: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-062";
pub fn rwa_vault_control_root_062(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_062,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_063: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-063";
pub fn rwa_vault_control_root_063(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_063,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_064: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-064";
pub fn rwa_vault_control_root_064(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_064,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_065: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-065";
pub fn rwa_vault_control_root_065(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_065,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_066: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-066";
pub fn rwa_vault_control_root_066(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_066,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_067: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-067";
pub fn rwa_vault_control_root_067(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_067,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_068: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-068";
pub fn rwa_vault_control_root_068(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_068,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_069: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-069";
pub fn rwa_vault_control_root_069(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_069,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_070: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-070";
pub fn rwa_vault_control_root_070(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_070,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_071: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-071";
pub fn rwa_vault_control_root_071(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_071,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_072: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-072";
pub fn rwa_vault_control_root_072(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_072,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_073: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-073";
pub fn rwa_vault_control_root_073(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_073,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_074: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-074";
pub fn rwa_vault_control_root_074(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_074,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_075: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-075";
pub fn rwa_vault_control_root_075(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_075,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_076: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-076";
pub fn rwa_vault_control_root_076(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_076,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_077: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-077";
pub fn rwa_vault_control_root_077(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_077,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_078: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-078";
pub fn rwa_vault_control_root_078(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_078,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_079: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-079";
pub fn rwa_vault_control_root_079(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_079,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_080: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-080";
pub fn rwa_vault_control_root_080(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_080,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_081: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-081";
pub fn rwa_vault_control_root_081(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_081,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_082: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-082";
pub fn rwa_vault_control_root_082(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_082,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_083: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-083";
pub fn rwa_vault_control_root_083(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_083,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_084: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-084";
pub fn rwa_vault_control_root_084(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_084,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_085: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-085";
pub fn rwa_vault_control_root_085(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_085,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_086: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-086";
pub fn rwa_vault_control_root_086(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_086,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_087: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-087";
pub fn rwa_vault_control_root_087(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_087,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_088: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-088";
pub fn rwa_vault_control_root_088(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_088,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_089: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-089";
pub fn rwa_vault_control_root_089(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_089,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_090: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-090";
pub fn rwa_vault_control_root_090(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_090,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_091: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-091";
pub fn rwa_vault_control_root_091(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_091,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_092: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-092";
pub fn rwa_vault_control_root_092(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_092,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_093: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-093";
pub fn rwa_vault_control_root_093(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_093,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_094: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-094";
pub fn rwa_vault_control_root_094(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_094,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_095: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-095";
pub fn rwa_vault_control_root_095(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_095,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_096: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-096";
pub fn rwa_vault_control_root_096(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_096,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_097: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-097";
pub fn rwa_vault_control_root_097(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_097,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_098: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-098";
pub fn rwa_vault_control_root_098(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_098,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_099: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-099";
pub fn rwa_vault_control_root_099(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_099,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_100: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-100";
pub fn rwa_vault_control_root_100(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_100,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_101: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-101";
pub fn rwa_vault_control_root_101(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_101,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_102: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-102";
pub fn rwa_vault_control_root_102(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_102,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_103: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-103";
pub fn rwa_vault_control_root_103(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_103,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_104: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-104";
pub fn rwa_vault_control_root_104(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_104,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_105: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-105";
pub fn rwa_vault_control_root_105(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_105,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_106: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-106";
pub fn rwa_vault_control_root_106(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_106,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_107: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-107";
pub fn rwa_vault_control_root_107(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_107,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_108: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-108";
pub fn rwa_vault_control_root_108(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_108,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_109: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-109";
pub fn rwa_vault_control_root_109(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_109,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_110: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-110";
pub fn rwa_vault_control_root_110(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_110,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_111: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-111";
pub fn rwa_vault_control_root_111(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_111,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_112: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-112";
pub fn rwa_vault_control_root_112(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_112,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_113: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-113";
pub fn rwa_vault_control_root_113(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_113,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_114: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-114";
pub fn rwa_vault_control_root_114(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_114,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_115: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-115";
pub fn rwa_vault_control_root_115(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_115,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_116: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-116";
pub fn rwa_vault_control_root_116(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_116,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_117: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-117";
pub fn rwa_vault_control_root_117(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_117,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_118: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-118";
pub fn rwa_vault_control_root_118(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_118,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_119: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-119";
pub fn rwa_vault_control_root_119(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_119,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_120: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-120";
pub fn rwa_vault_control_root_120(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_120,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_121: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-121";
pub fn rwa_vault_control_root_121(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_121,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_122: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-122";
pub fn rwa_vault_control_root_122(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_122,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_123: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-123";
pub fn rwa_vault_control_root_123(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_123,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_124: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-124";
pub fn rwa_vault_control_root_124(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_124,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_125: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-125";
pub fn rwa_vault_control_root_125(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_125,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_126: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-126";
pub fn rwa_vault_control_root_126(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_126,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_127: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-127";
pub fn rwa_vault_control_root_127(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_127,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_128: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-128";
pub fn rwa_vault_control_root_128(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_128,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_129: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-129";
pub fn rwa_vault_control_root_129(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_129,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_130: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-130";
pub fn rwa_vault_control_root_130(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_130,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_131: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-131";
pub fn rwa_vault_control_root_131(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_131,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_132: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-132";
pub fn rwa_vault_control_root_132(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_132,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_133: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-133";
pub fn rwa_vault_control_root_133(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_133,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_134: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-134";
pub fn rwa_vault_control_root_134(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_134,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_135: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-135";
pub fn rwa_vault_control_root_135(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_135,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_136: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-136";
pub fn rwa_vault_control_root_136(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_136,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_137: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-137";
pub fn rwa_vault_control_root_137(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_137,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_138: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-138";
pub fn rwa_vault_control_root_138(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_138,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_139: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-139";
pub fn rwa_vault_control_root_139(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_139,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_140: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-140";
pub fn rwa_vault_control_root_140(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_140,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_141: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-141";
pub fn rwa_vault_control_root_141(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_141,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_142: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-142";
pub fn rwa_vault_control_root_142(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_142,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_143: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-143";
pub fn rwa_vault_control_root_143(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_143,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_144: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-144";
pub fn rwa_vault_control_root_144(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_144,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_145: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-145";
pub fn rwa_vault_control_root_145(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_145,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_146: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-146";
pub fn rwa_vault_control_root_146(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_146,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_147: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-147";
pub fn rwa_vault_control_root_147(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_147,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_148: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-148";
pub fn rwa_vault_control_root_148(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_148,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_149: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-149";
pub fn rwa_vault_control_root_149(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_149,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_150: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-150";
pub fn rwa_vault_control_root_150(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_150,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_151: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-151";
pub fn rwa_vault_control_root_151(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_151,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_152: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-152";
pub fn rwa_vault_control_root_152(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_152,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_153: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-153";
pub fn rwa_vault_control_root_153(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_153,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_154: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-154";
pub fn rwa_vault_control_root_154(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_154,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_155: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-155";
pub fn rwa_vault_control_root_155(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_155,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_156: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-156";
pub fn rwa_vault_control_root_156(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_156,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_157: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-157";
pub fn rwa_vault_control_root_157(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_157,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_158: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-158";
pub fn rwa_vault_control_root_158(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_158,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_159: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-159";
pub fn rwa_vault_control_root_159(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_159,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_160: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-160";
pub fn rwa_vault_control_root_160(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_160,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_161: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-161";
pub fn rwa_vault_control_root_161(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_161,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_162: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-162";
pub fn rwa_vault_control_root_162(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_162,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_163: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-163";
pub fn rwa_vault_control_root_163(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_163,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_164: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-164";
pub fn rwa_vault_control_root_164(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_164,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_165: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-165";
pub fn rwa_vault_control_root_165(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_165,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_166: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-166";
pub fn rwa_vault_control_root_166(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_166,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_167: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-167";
pub fn rwa_vault_control_root_167(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_167,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_168: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-168";
pub fn rwa_vault_control_root_168(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_168,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub const RWA_VAULT_CONTROL_DOMAIN_169: &str =
    "private-l2-pq-confidential-tokenized-rwa-vault-control-domain-169";
pub fn rwa_vault_control_root_169(subject: &str, payload: &Value) -> String {
    domain_hash(
        RWA_VAULT_CONTROL_DOMAIN_169,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_roots_are_stable() {
        let state = State::devnet();
        assert_eq!(
            state.state_root(),
            state_root_from_public_record(&state.public_record_without_root())
        );
        assert_eq!(devnet_state_root(), State::devnet().state_root());
    }

    #[test]
    fn public_record_contains_state_root() {
        let record = devnet_public_record();
        assert!(record.get("state_root").is_some());
    }
}
