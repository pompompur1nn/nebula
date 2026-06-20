use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-private-l2-pq-tokenized-contract-asset-registry-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_HEIGHT: u64 = 918_400;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_PQ_ATTESTATION_SUITE: &str =
    "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_PRIVACY_SUITE: &str =
    "monero-ringct-nullifier-fence+private-contract-note-commitments-v1";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_TRANSFER_RULE_SUITE: &str =
    "private-transfer-rule-certificate-v1";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_SPONSOR_SUITE: &str =
    "low-fee-private-fee-sponsor-reservation-v1";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_RECEIPT_SUITE: &str =
    "private-mint-burn-settlement-receipt-v1";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_REBATE_SUITE: &str =
    "low-fee-private-registry-rebate-v1";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    65_536;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_TARGET_PRIVACY_SET: u64 =
    131_072;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 =
    24;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_CERT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 32;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS:
    u64 = 12;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS: u64 =
    720;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_MAX_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_REBATE_BPS: u64 = 8;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_ASSET_CLASSES: usize =
    262_144;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_ISSUANCE_COMMITMENTS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_TRANSFER_RULE_CERTS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_SPONSOR_RESERVATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_RECEIPTS: usize = 2_097_152;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_REBATES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_PRIVACY_FENCES: usize =
    4_194_304;
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_REGISTRY_ID: &str =
    "private-l2-pq-tokenized-contract-asset-registry-devnet";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_WATCHER_SET_ID: &str =
    "private-l2-pq-tokenized-contract-asset-registry-watchers";
pub const PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_REPLAY_DOMAIN: &str =
    "monero-private-l2-pq-tokenized-contract-asset-registry-devnet";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetClassKind {
    ConfidentialFungibleToken,
    WrappedMoneroContractClaim,
    PrivateStableAsset,
    TokenizedVaultShare,
    TokenizedRwaReceipt,
    ConfidentialLpPosition,
    SyntheticDerivative,
    GovernanceNote,
    SettlementCoupon,
    RebateCredit,
}

impl AssetClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialFungibleToken => "confidential_fungible_token",
            Self::WrappedMoneroContractClaim => "wrapped_monero_contract_claim",
            Self::PrivateStableAsset => "private_stable_asset",
            Self::TokenizedVaultShare => "tokenized_vault_share",
            Self::TokenizedRwaReceipt => "tokenized_rwa_receipt",
            Self::ConfidentialLpPosition => "confidential_lp_position",
            Self::SyntheticDerivative => "synthetic_derivative",
            Self::GovernanceNote => "governance_note",
            Self::SettlementCoupon => "settlement_coupon",
            Self::RebateCredit => "rebate_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractRuntimeKind {
    WasmZk,
    EvmCompatible,
    NativeConfidentialPrecompile,
    MoneroBridgeAdapter,
    DefiVaultStrategy,
    SettlementHook,
}

impl ContractRuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WasmZk => "wasm_zk",
            Self::EvmCompatible => "evm_compatible",
            Self::NativeConfidentialPrecompile => "native_confidential_precompile",
            Self::MoneroBridgeAdapter => "monero_bridge_adapter",
            Self::DefiVaultStrategy => "defi_vault_strategy",
            Self::SettlementHook => "settlement_hook",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryLane {
    SponsoredLowFee,
    Fast,
    Standard,
    Bulk,
    Emergency,
}

impl RegistryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Bulk => "bulk",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::Bulk => config.max_fee_bps / 2,
            Self::Standard => config.max_fee_bps.saturating_mul(2) / 3,
            Self::Fast | Self::Emergency => config.max_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetClassStatus {
    Draft,
    Proposed,
    Attested,
    Active,
    Frozen,
    Retiring,
    Retired,
}

impl AssetClassStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceStatus {
    Committed,
    PrivacyChecked,
    RuleCertified,
    SponsorReserved,
    Minted,
    Burned,
    Settled,
    Rejected,
    Expired,
}

impl IssuanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::PrivacyChecked => "privacy_checked",
            Self::RuleCertified => "rule_certified",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Minted => "minted",
            Self::Burned => "burned",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Verified,
    Bound,
    Revoked,
    Expired,
    Disputed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::Bound => "bound",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferRuleKind {
    OpenPrivateTransfer,
    AllowlistCommitment,
    JurisdictionFence,
    VelocityLimit,
    NftLikeSingleton,
    VaultShareLockup,
    BridgeSettlementOnly,
    ContractHookRequired,
}

impl TransferRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenPrivateTransfer => "open_private_transfer",
            Self::AllowlistCommitment => "allowlist_commitment",
            Self::JurisdictionFence => "jurisdiction_fence",
            Self::VelocityLimit => "velocity_limit",
            Self::NftLikeSingleton => "nft_like_singleton",
            Self::VaultShareLockup => "vault_share_lockup",
            Self::BridgeSettlementOnly => "bridge_settlement_only",
            Self::ContractHookRequired => "contract_hook_required",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Proposed,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl CertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Open,
    Locked,
    Consumed,
    Released,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Mint,
    Burn,
    Settlement,
    SponsorDebit,
    RuleUpdate,
    ContractCall,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Settlement => "settlement",
            Self::SponsorDebit => "sponsor_debit",
            Self::RuleUpdate => "rule_update",
            Self::ContractCall => "contract_call",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
    Reverted,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Claimed,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Nullifier,
    Commitment,
    ReplayDomain,
    ViewTag,
    ContractEvent,
    SettlementAnchor,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::Commitment => "commitment",
            Self::ReplayDomain => "replay_domain",
            Self::ViewTag => "view_tag",
            Self::ContractEvent => "contract_event",
            Self::SettlementAnchor => "settlement_anchor",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub registry_id: String,
    pub watcher_set_id: String,
    pub replay_domain: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub privacy_suite: String,
    pub transfer_rule_suite: String,
    pub sponsor_suite: String,
    pub receipt_suite: String,
    pub rebate_suite: String,
    pub min_privacy_set: u64,
    pub target_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub batch_ttl_blocks: u64,
    pub cert_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub low_fee_bps: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            l2_network: PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            registry_id:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_REGISTRY_ID
                    .to_string(),
            watcher_set_id:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_WATCHER_SET_ID
                    .to_string(),
            replay_domain:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_REPLAY_DOMAIN
                    .to_string(),
            hash_suite: PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_HASH_SUITE
                .to_string(),
            pq_attestation_suite:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_PQ_ATTESTATION_SUITE
                    .to_string(),
            privacy_suite: PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_PRIVACY_SUITE
                .to_string(),
            transfer_rule_suite:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_TRANSFER_RULE_SUITE
                    .to_string(),
            sponsor_suite: PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_SPONSOR_SUITE
                .to_string(),
            receipt_suite: PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_RECEIPT_SUITE
                .to_string(),
            rebate_suite: PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_REBATE_SUITE
                .to_string(),
            min_privacy_set:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_TARGET_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            batch_ttl_blocks:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            cert_ttl_blocks:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_CERT_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_window_blocks:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            rebate_ttl_blocks:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS,
            low_fee_bps:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_fee_bps:
                PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_MAX_FEE_BPS,
            rebate_bps: PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEFAULT_REBATE_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            !self.monero_network.trim().is_empty(),
            "monero network required",
        )?;
        require(!self.l2_network.trim().is_empty(), "l2 network required")?;
        require(!self.registry_id.trim().is_empty(), "registry id required")?;
        require(
            !self.watcher_set_id.trim().is_empty(),
            "watcher set required",
        )?;
        require(
            !self.replay_domain.trim().is_empty(),
            "replay domain required",
        )?;
        require(
            self.min_privacy_set <= self.target_privacy_set,
            "min privacy set exceeds target",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(
            self.low_fee_bps <= self.max_fee_bps
                && self.max_fee_bps
                    <= PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_BPS,
            "invalid fee bps",
        )?;
        require(
            self.rebate_bps <= PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_BPS,
            "invalid rebate bps",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "registry_id": self.registry_id,
            "watcher_set_id": self.watcher_set_id,
            "replay_domain": self.replay_domain,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "privacy_suite": self.privacy_suite,
            "transfer_rule_suite": self.transfer_rule_suite,
            "sponsor_suite": self.sponsor_suite,
            "receipt_suite": self.receipt_suite,
            "rebate_suite": self.rebate_suite,
            "min_privacy_set": self.min_privacy_set,
            "target_privacy_set": self.target_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "cert_ttl_blocks": self.cert_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "low_fee_bps": self.low_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PRIVATE-L2-PQ-TCAR-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub asset_classes: u64,
    pub issuance_commitments: u64,
    pub pq_attestations: u64,
    pub transfer_rule_certificates: u64,
    pub fee_sponsor_reservations: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub public_records: u64,
    pub finalized_settlements: u64,
    pub total_sponsored_fee_units: u128,
    pub total_rebate_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_classes": self.asset_classes,
            "issuance_commitments": self.issuance_commitments,
            "pq_attestations": self.pq_attestations,
            "transfer_rule_certificates": self.transfer_rule_certificates,
            "fee_sponsor_reservations": self.fee_sponsor_reservations,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "privacy_fences": self.privacy_fences,
            "public_records": self.public_records,
            "finalized_settlements": self.finalized_settlements,
            "total_sponsored_fee_units": self.total_sponsored_fee_units.to_string(),
            "total_rebate_units": self.total_rebate_units.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PRIVATE-L2-PQ-TCAR-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenizedContractAssetClass {
    pub asset_class_id: String,
    pub symbol_commitment: String,
    pub metadata_commitment: String,
    pub issuer_commitment: String,
    pub contract_id: String,
    pub runtime_kind: ContractRuntimeKind,
    pub asset_kind: AssetClassKind,
    pub status: AssetClassStatus,
    pub decimals: u8,
    pub supply_cap_commitment: String,
    pub supply_commitment_root: String,
    pub authority_root: String,
    pub transfer_rule_root: String,
    pub privacy_policy_root: String,
    pub contract_state_root: String,
    pub pq_attestation_root: String,
    pub monero_anchor_root: String,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: String,
}

impl TokenizedContractAssetClass {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_class_id": self.asset_class_id,
            "symbol_commitment": self.symbol_commitment,
            "metadata_commitment": self.metadata_commitment,
            "issuer_commitment": self.issuer_commitment,
            "contract_id": self.contract_id,
            "runtime_kind": self.runtime_kind.as_str(),
            "asset_kind": self.asset_kind.as_str(),
            "status": self.status.as_str(),
            "decimals": self.decimals,
            "supply_cap_commitment": self.supply_cap_commitment,
            "supply_commitment_root": self.supply_commitment_root,
            "authority_root": self.authority_root,
            "transfer_rule_root": self.transfer_rule_root,
            "privacy_policy_root": self.privacy_policy_root,
            "contract_state_root": self.contract_state_root,
            "pq_attestation_root": self.pq_attestation_root,
            "monero_anchor_root": self.monero_anchor_root,
            "registered_at_height": self.registered_at_height,
            "updated_at_height": self.updated_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PRIVATE-L2-PQ-TCAR-ASSET-CLASS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateIssuanceCommitment {
    pub commitment_id: String,
    pub asset_class_id: String,
    pub issuer_commitment: String,
    pub recipient_set_root: String,
    pub amount_commitment_root: String,
    pub blinding_root: String,
    pub supply_delta_commitment: String,
    pub nullifier_fence_root: String,
    pub transfer_rule_certificate_id: String,
    pub sponsor_reservation_id: String,
    pub lane: RegistryLane,
    pub status: IssuanceStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl PrivateIssuanceCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "asset_class_id": self.asset_class_id,
            "issuer_commitment": self.issuer_commitment,
            "recipient_set_root": self.recipient_set_root,
            "amount_commitment_root": self.amount_commitment_root,
            "blinding_root": self.blinding_root,
            "supply_delta_commitment": self.supply_delta_commitment,
            "nullifier_fence_root": self.nullifier_fence_root,
            "transfer_rule_certificate_id": self.transfer_rule_certificate_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TCAR-ISSUANCE-COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqContractAttestation {
    pub attestation_id: String,
    pub asset_class_id: String,
    pub contract_id: String,
    pub runtime_kind: ContractRuntimeKind,
    pub bytecode_root: String,
    pub abi_root: String,
    pub circuit_root: String,
    pub key_package_root: String,
    pub pq_signature_root: String,
    pub signer_committee_root: String,
    pub min_security_bits: u16,
    pub status: AttestationStatus,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl PqContractAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "asset_class_id": self.asset_class_id,
            "contract_id": self.contract_id,
            "runtime_kind": self.runtime_kind.as_str(),
            "bytecode_root": self.bytecode_root,
            "abi_root": self.abi_root,
            "circuit_root": self.circuit_root,
            "key_package_root": self.key_package_root,
            "pq_signature_root": self.pq_signature_root,
            "signer_committee_root": self.signer_committee_root,
            "min_security_bits": self.min_security_bits,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TCAR-PQ-CONTRACT-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferRuleCertificate {
    pub certificate_id: String,
    pub asset_class_id: String,
    pub rule_kind: TransferRuleKind,
    pub rule_commitment_root: String,
    pub proof_system_root: String,
    pub issuer_commitment: String,
    pub compliance_committee_root: String,
    pub pq_signature_root: String,
    pub status: CertificateStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl TransferRuleCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "asset_class_id": self.asset_class_id,
            "rule_kind": self.rule_kind.as_str(),
            "rule_commitment_root": self.rule_commitment_root,
            "proof_system_root": self.proof_system_root,
            "issuer_commitment": self.issuer_commitment,
            "compliance_committee_root": self.compliance_committee_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TCAR-TRANSFER-RULE-CERT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub asset_class_id: String,
    pub commitment_id: String,
    pub lane: RegistryLane,
    pub max_fee_units: u128,
    pub reserved_fee_units: u128,
    pub sponsored_fee_bps: u64,
    pub privacy_budget_root: String,
    pub status: ReservationStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl FeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_class_id": self.asset_class_id,
            "commitment_id": self.commitment_id,
            "lane": self.lane.as_str(),
            "max_fee_units": self.max_fee_units.to_string(),
            "reserved_fee_units": self.reserved_fee_units.to_string(),
            "sponsored_fee_bps": self.sponsored_fee_bps,
            "privacy_budget_root": self.privacy_budget_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TCAR-FEE-SPONSOR-RESERVATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MintBurnSettlementReceipt {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub asset_class_id: String,
    pub commitment_id: String,
    pub contract_id: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub amount_delta_commitment: String,
    pub sponsor_reservation_id: String,
    pub settlement_anchor_root: String,
    pub pq_proof_root: String,
    pub status: ReceiptStatus,
    pub finalized_at_height: u64,
    pub nonce: String,
}

impl MintBurnSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "asset_class_id": self.asset_class_id,
            "commitment_id": self.commitment_id,
            "contract_id": self.contract_id,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "amount_delta_commitment": self.amount_delta_commitment,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "settlement_anchor_root": self.settlement_anchor_root,
            "pq_proof_root": self.pq_proof_root,
            "status": self.status.as_str(),
            "finalized_at_height": self.finalized_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PRIVATE-L2-PQ-TCAR-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCredit {
    pub rebate_id: String,
    pub beneficiary_commitment: String,
    pub asset_class_id: String,
    pub source_receipt_id: String,
    pub sponsor_reservation_id: String,
    pub rebate_units: u128,
    pub rebate_bps: u64,
    pub claim_commitment_root: String,
    pub status: RebateStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl RebateCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_class_id": self.asset_class_id,
            "source_receipt_id": self.source_receipt_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "rebate_units": self.rebate_units.to_string(),
            "rebate_bps": self.rebate_bps,
            "claim_commitment_root": self.claim_commitment_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PRIVATE-L2-PQ-TCAR-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub asset_class_id: String,
    pub nullifier_root: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub view_tag_root: String,
    pub consumed: bool,
    pub recorded_at_height: u64,
    pub nonce: String,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "subject_id": self.subject_id,
            "asset_class_id": self.asset_class_id,
            "nullifier_root": self.nullifier_root,
            "commitment_root": self.commitment_root,
            "replay_domain": self.replay_domain,
            "view_tag_root": self.view_tag_root,
            "consumed": self.consumed,
            "recorded_at_height": self.recorded_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PRIVATE-L2-PQ-TCAR-PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecordEntry {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root: String,
    pub published_at_height: u64,
}

impl PublicRecordEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "state_root": self.state_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub asset_class_root: String,
    pub issuance_commitment_root: String,
    pub pq_attestation_root: String,
    pub transfer_rule_certificate_root: String,
    pub fee_sponsor_reservation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "asset_class_root": self.asset_class_root,
            "issuance_commitment_root": self.issuance_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "transfer_rule_certificate_root": self.transfer_rule_certificate_root,
            "fee_sponsor_reservation_root": self.fee_sponsor_reservation_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub asset_classes: BTreeMap<String, TokenizedContractAssetClass>,
    pub issuance_commitments: BTreeMap<String, PrivateIssuanceCommitment>,
    pub pq_attestations: BTreeMap<String, PqContractAttestation>,
    pub transfer_rule_certificates: BTreeMap<String, TransferRuleCertificate>,
    pub fee_sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub receipts: BTreeMap<String, MintBurnSettlementReceipt>,
    pub rebates: BTreeMap<String, RebateCredit>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub public_records: BTreeMap<String, PublicRecordEntry>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub finalized_receipts: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            asset_classes: BTreeMap::new(),
            issuance_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            transfer_rule_certificates: BTreeMap::new(),
            fee_sponsor_reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            finalized_receipts: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone()).expect("valid devnet config");
        let base_height = PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_DEVNET_HEIGHT;
        let wxmr_asset = devnet_asset_class(
            &config,
            "wxmr-private-contract-share",
            "WXMR",
            AssetClassKind::WrappedMoneroContractClaim,
            ContractRuntimeKind::MoneroBridgeAdapter,
            base_height,
            "0",
        );
        let vault_asset = devnet_asset_class(
            &config,
            "vault-alpha-private-share",
            "vALPHA",
            AssetClassKind::TokenizedVaultShare,
            ContractRuntimeKind::DefiVaultStrategy,
            base_height + 1,
            "1",
        );
        state
            .insert_asset_class(wxmr_asset.clone())
            .expect("devnet wxmr asset");
        state
            .insert_asset_class(vault_asset.clone())
            .expect("devnet vault asset");
        let wxmr_attestation = devnet_attestation(&config, &wxmr_asset, base_height + 2, "0");
        let vault_attestation = devnet_attestation(&config, &vault_asset, base_height + 3, "1");
        state
            .insert_pq_attestation(wxmr_attestation)
            .expect("devnet wxmr attestation");
        state
            .insert_pq_attestation(vault_attestation)
            .expect("devnet vault attestation");
        let wxmr_cert = devnet_transfer_rule_certificate(
            &config,
            &wxmr_asset,
            TransferRuleKind::BridgeSettlementOnly,
            base_height + 4,
            "0",
        );
        let vault_cert = devnet_transfer_rule_certificate(
            &config,
            &vault_asset,
            TransferRuleKind::VaultShareLockup,
            base_height + 5,
            "1",
        );
        state
            .insert_transfer_rule_certificate(wxmr_cert.clone())
            .expect("devnet wxmr cert");
        state
            .insert_transfer_rule_certificate(vault_cert.clone())
            .expect("devnet vault cert");
        let wxmr_reservation = devnet_sponsor_reservation(
            &config,
            &wxmr_asset,
            "devnet-wxmr-mint",
            RegistryLane::SponsoredLowFee,
            base_height + 6,
            "0",
        );
        let vault_reservation = devnet_sponsor_reservation(
            &config,
            &vault_asset,
            "devnet-vault-settlement",
            RegistryLane::Fast,
            base_height + 7,
            "1",
        );
        state
            .insert_fee_sponsor_reservation(wxmr_reservation.clone())
            .expect("devnet wxmr sponsor");
        state
            .insert_fee_sponsor_reservation(vault_reservation.clone())
            .expect("devnet vault sponsor");
        let wxmr_commitment = devnet_issuance_commitment(
            &config,
            &wxmr_asset,
            &wxmr_cert,
            &wxmr_reservation,
            RegistryLane::SponsoredLowFee,
            base_height + 8,
            "0",
        );
        let vault_commitment = devnet_issuance_commitment(
            &config,
            &vault_asset,
            &vault_cert,
            &vault_reservation,
            RegistryLane::Fast,
            base_height + 9,
            "1",
        );
        state
            .insert_issuance_commitment(wxmr_commitment.clone())
            .expect("devnet wxmr commitment");
        state
            .insert_issuance_commitment(vault_commitment.clone())
            .expect("devnet vault commitment");
        let wxmr_fence = devnet_privacy_fence(
            &config,
            &wxmr_asset,
            &wxmr_commitment.commitment_id,
            FenceKind::Nullifier,
            base_height + 10,
            "0",
        );
        let vault_fence = devnet_privacy_fence(
            &config,
            &vault_asset,
            &vault_commitment.commitment_id,
            FenceKind::Commitment,
            base_height + 11,
            "1",
        );
        state
            .insert_privacy_fence(wxmr_fence)
            .expect("devnet wxmr fence");
        state
            .insert_privacy_fence(vault_fence)
            .expect("devnet vault fence");
        let wxmr_receipt = devnet_receipt(
            &config,
            &wxmr_asset,
            &wxmr_commitment,
            &wxmr_reservation,
            ReceiptKind::Mint,
            base_height + 12,
            "0",
        );
        let vault_receipt = devnet_receipt(
            &config,
            &vault_asset,
            &vault_commitment,
            &vault_reservation,
            ReceiptKind::Settlement,
            base_height + 13,
            "1",
        );
        state
            .insert_receipt(wxmr_receipt.clone())
            .expect("devnet wxmr receipt");
        state
            .insert_receipt(vault_receipt.clone())
            .expect("devnet vault receipt");
        let wxmr_rebate = devnet_rebate(
            &config,
            &wxmr_asset,
            &wxmr_receipt,
            &wxmr_reservation,
            base_height + 14,
            "0",
        );
        let vault_rebate = devnet_rebate(
            &config,
            &vault_asset,
            &vault_receipt,
            &vault_reservation,
            base_height + 15,
            "1",
        );
        state
            .insert_rebate(wxmr_rebate)
            .expect("devnet wxmr rebate");
        state
            .insert_rebate(vault_rebate)
            .expect("devnet vault rebate");
        state.rebuild_public_records(base_height + 16);
        state
    }

    pub fn insert_asset_class(
        &mut self,
        asset: TokenizedContractAssetClass,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.asset_classes.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_ASSET_CLASSES,
            "asset class capacity exceeded",
        )?;
        require(!asset.asset_class_id.trim().is_empty(), "asset id required")?;
        require(
            !self.asset_classes.contains_key(&asset.asset_class_id),
            "duplicate asset class",
        )?;
        self.asset_classes
            .insert(asset.asset_class_id.clone(), asset);
        Ok(())
    }

    pub fn insert_issuance_commitment(
        &mut self,
        commitment: PrivateIssuanceCommitment,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.issuance_commitments.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_ISSUANCE_COMMITMENTS,
            "issuance commitment capacity exceeded",
        )?;
        require(
            self.asset_classes.contains_key(&commitment.asset_class_id),
            "unknown asset class",
        )?;
        require(
            !self
                .issuance_commitments
                .contains_key(&commitment.commitment_id),
            "duplicate issuance commitment",
        )?;
        self.issuance_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqContractAttestation,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.pq_attestations.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_ATTESTATIONS,
            "attestation capacity exceeded",
        )?;
        require(
            attestation.min_security_bits >= self.config.min_pq_security_bits,
            "attestation below pq security floor",
        )?;
        require(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate attestation",
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_transfer_rule_certificate(
        &mut self,
        cert: TransferRuleCertificate,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.transfer_rule_certificates.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_TRANSFER_RULE_CERTS,
            "transfer rule certificate capacity exceeded",
        )?;
        require(
            self.asset_classes.contains_key(&cert.asset_class_id),
            "unknown asset class",
        )?;
        require(
            !self
                .transfer_rule_certificates
                .contains_key(&cert.certificate_id),
            "duplicate transfer rule certificate",
        )?;
        self.transfer_rule_certificates
            .insert(cert.certificate_id.clone(), cert);
        Ok(())
    }

    pub fn insert_fee_sponsor_reservation(
        &mut self,
        reservation: FeeSponsorReservation,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.fee_sponsor_reservations.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_SPONSOR_RESERVATIONS,
            "sponsor reservation capacity exceeded",
        )?;
        require(
            reservation.sponsored_fee_bps
                <= PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_BPS,
            "invalid sponsor fee bps",
        )?;
        require(
            !self
                .fee_sponsor_reservations
                .contains_key(&reservation.reservation_id),
            "duplicate sponsor reservation",
        )?;
        self.fee_sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: MintBurnSettlementReceipt,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.receipts.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_RECEIPTS,
            "receipt capacity exceeded",
        )?;
        require(
            self.asset_classes.contains_key(&receipt.asset_class_id),
            "unknown asset class",
        )?;
        require(
            !self.receipts.contains_key(&receipt.receipt_id),
            "duplicate receipt",
        )?;
        if receipt.status == ReceiptStatus::Finalized {
            self.finalized_receipts.insert(receipt.receipt_id.clone());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_rebate(
        &mut self,
        rebate: RebateCredit,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.rebates.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_REBATES,
            "rebate capacity exceeded",
        )?;
        require(
            rebate.rebate_bps <= PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_BPS,
            "invalid rebate bps",
        )?;
        require(
            !self.rebates.contains_key(&rebate.rebate_id),
            "duplicate rebate",
        )?;
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn insert_privacy_fence(
        &mut self,
        fence: PrivacyNullifierFence,
    ) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
        require(
            self.privacy_fences.len()
                < PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_PRIVACY_FENCES,
            "privacy fence capacity exceeded",
        )?;
        require(
            !self.privacy_fences.contains_key(&fence.fence_id),
            "duplicate privacy fence",
        )?;
        if fence.consumed {
            self.consumed_nullifiers
                .insert(fence.nullifier_root.clone());
        }
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            asset_classes: self.asset_classes.len() as u64,
            issuance_commitments: self.issuance_commitments.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            transfer_rule_certificates: self.transfer_rule_certificates.len() as u64,
            fee_sponsor_reservations: self.fee_sponsor_reservations.len() as u64,
            receipts: self.receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            public_records: self.public_records.len() as u64,
            finalized_settlements: self.finalized_receipts.len() as u64,
            total_sponsored_fee_units: self
                .fee_sponsor_reservations
                .values()
                .map(|reservation| reservation.reserved_fee_units)
                .sum(),
            total_rebate_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: self.config.root(),
            asset_class_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-ASSET-CLASS-ROOT",
                self.asset_classes
                    .values()
                    .map(TokenizedContractAssetClass::public_record),
            ),
            issuance_commitment_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-ISSUANCE-COMMITMENT-ROOT",
                self.issuance_commitments
                    .values()
                    .map(PrivateIssuanceCommitment::public_record),
            ),
            pq_attestation_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-PQ-ATTESTATION-ROOT",
                self.pq_attestations
                    .values()
                    .map(PqContractAttestation::public_record),
            ),
            transfer_rule_certificate_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-TRANSFER-RULE-CERTIFICATE-ROOT",
                self.transfer_rule_certificates
                    .values()
                    .map(TransferRuleCertificate::public_record),
            ),
            fee_sponsor_reservation_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-FEE-SPONSOR-RESERVATION-ROOT",
                self.fee_sponsor_reservations
                    .values()
                    .map(FeeSponsorReservation::public_record),
            ),
            receipt_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-RECEIPT-ROOT",
                self.receipts
                    .values()
                    .map(MintBurnSettlementReceipt::public_record),
            ),
            rebate_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-REBATE-ROOT",
                self.rebates.values().map(RebateCredit::public_record),
            ),
            privacy_fence_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-PRIVACY-FENCE-ROOT",
                self.privacy_fences
                    .values()
                    .map(PrivacyNullifierFence::public_record),
            ),
            public_record_root: merkle_records(
                "PRIVATE-L2-PQ-TCAR-PUBLIC-RECORD-ROOT",
                self.public_records
                    .values()
                    .map(PublicRecordEntry::public_record),
            ),
            counters_root: counters.root(),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_roots(&roots);
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn rebuild_public_records(&mut self, height: u64) {
        self.public_records.clear();
        let mut records = Vec::new();
        records.extend(self.asset_classes.values().map(|asset| {
            public_record_entry(
                "asset_class",
                &asset.asset_class_id,
                asset.public_record(),
                height,
            )
        }));
        records.extend(self.issuance_commitments.values().map(|commitment| {
            public_record_entry(
                "issuance_commitment",
                &commitment.commitment_id,
                commitment.public_record(),
                height,
            )
        }));
        records.extend(self.pq_attestations.values().map(|attestation| {
            public_record_entry(
                "pq_contract_attestation",
                &attestation.attestation_id,
                attestation.public_record(),
                height,
            )
        }));
        records.extend(self.transfer_rule_certificates.values().map(|cert| {
            public_record_entry(
                "transfer_rule_certificate",
                &cert.certificate_id,
                cert.public_record(),
                height,
            )
        }));
        records.extend(self.fee_sponsor_reservations.values().map(|reservation| {
            public_record_entry(
                "fee_sponsor_reservation",
                &reservation.reservation_id,
                reservation.public_record(),
                height,
            )
        }));
        records.extend(self.receipts.values().map(|receipt| {
            public_record_entry(
                "receipt",
                &receipt.receipt_id,
                receipt.public_record(),
                height,
            )
        }));
        records.extend(self.rebates.values().map(|rebate| {
            public_record_entry("rebate", &rebate.rebate_id, rebate.public_record(), height)
        }));
        records.extend(self.privacy_fences.values().map(|fence| {
            public_record_entry(
                "privacy_fence",
                &fence.fence_id,
                fence.public_record(),
                height,
            )
        }));
        for record in records {
            self.public_records.insert(record.record_id.clone(), record);
        }
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-PAYLOAD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-TCAR-PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-TCAR-STATE", record)
}

pub fn asset_class_id(
    issuer_commitment: &str,
    contract_id: &str,
    asset_kind: AssetClassKind,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-ASSET-CLASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(issuer_commitment),
            HashPart::Str(contract_id),
            HashPart::Str(asset_kind.as_str()),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn contract_id(runtime_kind: ContractRuntimeKind, bytecode_root: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-CONTRACT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(runtime_kind.as_str()),
            HashPart::Str(bytecode_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn issuance_commitment_id(
    asset_class_id: &str,
    issuer_commitment: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-ISSUANCE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(asset_class_id),
            HashPart::Str(issuer_commitment),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn pq_attestation_id(asset_class_id: &str, contract_id: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(asset_class_id),
            HashPart::Str(contract_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn transfer_rule_certificate_id(
    asset_class_id: &str,
    rule_kind: TransferRuleKind,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-TRANSFER-RULE-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(asset_class_id),
            HashPart::Str(rule_kind.as_str()),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn fee_sponsor_reservation_id(
    sponsor_commitment: &str,
    asset_class_id: &str,
    commitment_id: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-FEE-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(asset_class_id),
            HashPart::Str(commitment_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn receipt_id(
    receipt_kind: ReceiptKind,
    asset_class_id: &str,
    commitment_id: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_kind.as_str()),
            HashPart::Str(asset_class_id),
            HashPart::Str(commitment_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn rebate_id(beneficiary_commitment: &str, source_receipt_id: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(source_receipt_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    fence_kind: FenceKind,
    subject_id: &str,
    nullifier_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(fence_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn deterministic_commitment(label: &str, subject: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TCAR-DETERMINISTIC-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: &str) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "label": label,
        "subject": subject,
        "nonce": nonce,
    });
    root_from_record("PRIVATE-L2-PQ-TCAR-DETERMINISTIC-ROOT", &record)
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqTokenizedContractAssetRegistryRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn merkle_records<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let mut leaves = records.into_iter().collect::<Vec<Value>>();
    leaves.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &leaves)
}

fn state_root_from_roots(roots: &Roots) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "config_root": roots.config_root,
        "asset_class_root": roots.asset_class_root,
        "issuance_commitment_root": roots.issuance_commitment_root,
        "pq_attestation_root": roots.pq_attestation_root,
        "transfer_rule_certificate_root": roots.transfer_rule_certificate_root,
        "fee_sponsor_reservation_root": roots.fee_sponsor_reservation_root,
        "receipt_root": roots.receipt_root,
        "rebate_root": roots.rebate_root,
        "privacy_fence_root": roots.privacy_fence_root,
        "public_record_root": roots.public_record_root,
        "counters_root": roots.counters_root,
    });
    state_root_from_record(&record)
}

fn public_record_entry(
    kind: &str,
    subject_id: &str,
    payload: Value,
    height: u64,
) -> PublicRecordEntry {
    let payload_hash = payload_root(&payload);
    let record_state_root = state_root_from_record(&payload);
    let record_id = domain_hash(
        "PRIVATE-L2-PQ-TCAR-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Str(&payload_hash),
            HashPart::Int(height as i128),
        ],
        32,
    );
    PublicRecordEntry {
        record_id,
        record_kind: kind.to_string(),
        subject_id: subject_id.to_string(),
        payload_root: payload_hash,
        state_root: record_state_root,
        published_at_height: height,
    }
}

fn devnet_asset_class(
    config: &Config,
    label: &str,
    symbol: &str,
    asset_kind: AssetClassKind,
    runtime_kind: ContractRuntimeKind,
    height: u64,
    nonce: &str,
) -> TokenizedContractAssetClass {
    let bytecode_root = deterministic_root("devnet-bytecode", label, nonce);
    let contract = contract_id(runtime_kind, &bytecode_root, nonce);
    let issuer = deterministic_commitment("devnet-issuer", label, nonce);
    let asset_id = asset_class_id(&issuer, &contract, asset_kind, nonce);
    TokenizedContractAssetClass {
        asset_class_id: asset_id,
        symbol_commitment: deterministic_commitment("symbol", symbol, nonce),
        metadata_commitment: deterministic_commitment("metadata", label, nonce),
        issuer_commitment: issuer,
        contract_id: contract,
        runtime_kind,
        asset_kind,
        status: AssetClassStatus::Active,
        decimals: 12,
        supply_cap_commitment: deterministic_commitment("supply-cap", label, nonce),
        supply_commitment_root: deterministic_root("supply", label, nonce),
        authority_root: deterministic_root("authority", label, nonce),
        transfer_rule_root: deterministic_root("transfer-rule", label, nonce),
        privacy_policy_root: deterministic_root("privacy-policy", label, nonce),
        contract_state_root: deterministic_root("contract-state", label, nonce),
        pq_attestation_root: deterministic_root("pq-attestation", label, nonce),
        monero_anchor_root: deterministic_root(&config.monero_network, label, nonce),
        registered_at_height: height,
        updated_at_height: height,
        nonce: nonce.to_string(),
    }
}

fn devnet_attestation(
    config: &Config,
    asset: &TokenizedContractAssetClass,
    height: u64,
    nonce: &str,
) -> PqContractAttestation {
    PqContractAttestation {
        attestation_id: pq_attestation_id(&asset.asset_class_id, &asset.contract_id, nonce),
        asset_class_id: asset.asset_class_id.clone(),
        contract_id: asset.contract_id.clone(),
        runtime_kind: asset.runtime_kind,
        bytecode_root: deterministic_root("attested-bytecode", &asset.contract_id, nonce),
        abi_root: deterministic_root("contract-abi", &asset.contract_id, nonce),
        circuit_root: deterministic_root("contract-circuit", &asset.contract_id, nonce),
        key_package_root: deterministic_root("pq-key-package", &asset.contract_id, nonce),
        pq_signature_root: deterministic_root("pq-signature", &asset.contract_id, nonce),
        signer_committee_root: deterministic_root(
            &config.watcher_set_id,
            &asset.contract_id,
            nonce,
        ),
        min_security_bits: config.min_pq_security_bits,
        status: AttestationStatus::Bound,
        attested_at_height: height,
        expires_at_height: height + config.cert_ttl_blocks,
        nonce: nonce.to_string(),
    }
}

fn devnet_transfer_rule_certificate(
    config: &Config,
    asset: &TokenizedContractAssetClass,
    rule_kind: TransferRuleKind,
    height: u64,
    nonce: &str,
) -> TransferRuleCertificate {
    TransferRuleCertificate {
        certificate_id: transfer_rule_certificate_id(&asset.asset_class_id, rule_kind, nonce),
        asset_class_id: asset.asset_class_id.clone(),
        rule_kind,
        rule_commitment_root: deterministic_root("rule-commitment", &asset.asset_class_id, nonce),
        proof_system_root: deterministic_root("rule-proof-system", &asset.asset_class_id, nonce),
        issuer_commitment: asset.issuer_commitment.clone(),
        compliance_committee_root: deterministic_root(
            &config.transfer_rule_suite,
            &asset.asset_class_id,
            nonce,
        ),
        pq_signature_root: deterministic_root("rule-pq-signature", &asset.asset_class_id, nonce),
        status: CertificateStatus::Active,
        issued_at_height: height,
        expires_at_height: height + config.cert_ttl_blocks,
        nonce: nonce.to_string(),
    }
}

fn devnet_sponsor_reservation(
    config: &Config,
    asset: &TokenizedContractAssetClass,
    commitment_label: &str,
    lane: RegistryLane,
    height: u64,
    nonce: &str,
) -> FeeSponsorReservation {
    let sponsor = deterministic_commitment("fee-sponsor", commitment_label, nonce);
    let commitment = issuance_commitment_id(
        &asset.asset_class_id,
        &asset.issuer_commitment,
        commitment_label,
    );
    FeeSponsorReservation {
        reservation_id: fee_sponsor_reservation_id(
            &sponsor,
            &asset.asset_class_id,
            &commitment,
            nonce,
        ),
        sponsor_commitment: sponsor,
        asset_class_id: asset.asset_class_id.clone(),
        commitment_id: commitment,
        lane,
        max_fee_units: 1_000_000,
        reserved_fee_units: 125_000 + lane.fee_bps(config) as u128,
        sponsored_fee_bps: lane.fee_bps(config),
        privacy_budget_root: deterministic_root(
            "sponsor-privacy-budget",
            &asset.asset_class_id,
            nonce,
        ),
        status: ReservationStatus::Locked,
        opened_at_height: height,
        expires_at_height: height + config.reservation_ttl_blocks,
        nonce: nonce.to_string(),
    }
}

fn devnet_issuance_commitment(
    config: &Config,
    asset: &TokenizedContractAssetClass,
    cert: &TransferRuleCertificate,
    reservation: &FeeSponsorReservation,
    lane: RegistryLane,
    height: u64,
    nonce: &str,
) -> PrivateIssuanceCommitment {
    PrivateIssuanceCommitment {
        commitment_id: reservation.commitment_id.clone(),
        asset_class_id: asset.asset_class_id.clone(),
        issuer_commitment: asset.issuer_commitment.clone(),
        recipient_set_root: deterministic_root("recipient-set", &asset.asset_class_id, nonce),
        amount_commitment_root: deterministic_root("amounts", &asset.asset_class_id, nonce),
        blinding_root: deterministic_root("blindings", &asset.asset_class_id, nonce),
        supply_delta_commitment: deterministic_commitment(
            "supply-delta",
            &asset.asset_class_id,
            nonce,
        ),
        nullifier_fence_root: deterministic_root(
            "issuance-nullifiers",
            &asset.asset_class_id,
            nonce,
        ),
        transfer_rule_certificate_id: cert.certificate_id.clone(),
        sponsor_reservation_id: reservation.reservation_id.clone(),
        lane,
        status: IssuanceStatus::SponsorReserved,
        opened_at_height: height,
        expires_at_height: height + config.batch_ttl_blocks,
        nonce: nonce.to_string(),
    }
}

fn devnet_privacy_fence(
    config: &Config,
    asset: &TokenizedContractAssetClass,
    subject_id: &str,
    fence_kind: FenceKind,
    height: u64,
    nonce: &str,
) -> PrivacyNullifierFence {
    let nullifier_root = deterministic_root("nullifier", subject_id, nonce);
    PrivacyNullifierFence {
        fence_id: privacy_fence_id(fence_kind, subject_id, &nullifier_root, nonce),
        fence_kind,
        subject_id: subject_id.to_string(),
        asset_class_id: asset.asset_class_id.clone(),
        nullifier_root,
        commitment_root: deterministic_root("fence-commitment", subject_id, nonce),
        replay_domain: config.replay_domain.clone(),
        view_tag_root: deterministic_root("view-tags", subject_id, nonce),
        consumed: matches!(fence_kind, FenceKind::Nullifier),
        recorded_at_height: height,
        nonce: nonce.to_string(),
    }
}

fn devnet_receipt(
    _config: &Config,
    asset: &TokenizedContractAssetClass,
    commitment: &PrivateIssuanceCommitment,
    reservation: &FeeSponsorReservation,
    receipt_kind: ReceiptKind,
    height: u64,
    nonce: &str,
) -> MintBurnSettlementReceipt {
    MintBurnSettlementReceipt {
        receipt_id: receipt_id(
            receipt_kind,
            &asset.asset_class_id,
            &commitment.commitment_id,
            nonce,
        ),
        receipt_kind,
        asset_class_id: asset.asset_class_id.clone(),
        commitment_id: commitment.commitment_id.clone(),
        contract_id: asset.contract_id.clone(),
        input_nullifier_root: deterministic_root(
            "receipt-input-nullifiers",
            &commitment.commitment_id,
            nonce,
        ),
        output_commitment_root: deterministic_root(
            "receipt-output-commitments",
            &commitment.commitment_id,
            nonce,
        ),
        amount_delta_commitment: deterministic_commitment(
            "receipt-amount-delta",
            &commitment.commitment_id,
            nonce,
        ),
        sponsor_reservation_id: reservation.reservation_id.clone(),
        settlement_anchor_root: deterministic_root(
            "settlement-anchor",
            &commitment.commitment_id,
            nonce,
        ),
        pq_proof_root: deterministic_root("receipt-pq-proof", &commitment.commitment_id, nonce),
        status: ReceiptStatus::Finalized,
        finalized_at_height: height,
        nonce: nonce.to_string(),
    }
}

fn devnet_rebate(
    config: &Config,
    asset: &TokenizedContractAssetClass,
    receipt: &MintBurnSettlementReceipt,
    reservation: &FeeSponsorReservation,
    height: u64,
    nonce: &str,
) -> RebateCredit {
    let beneficiary = deterministic_commitment("rebate-beneficiary", &receipt.receipt_id, nonce);
    RebateCredit {
        rebate_id: rebate_id(&beneficiary, &receipt.receipt_id, nonce),
        beneficiary_commitment: beneficiary,
        asset_class_id: asset.asset_class_id.clone(),
        source_receipt_id: receipt.receipt_id.clone(),
        sponsor_reservation_id: reservation.reservation_id.clone(),
        rebate_units: reservation
            .reserved_fee_units
            .saturating_mul(config.rebate_bps as u128)
            / PRIVATE_L2_PQ_TOKENIZED_CONTRACT_ASSET_REGISTRY_RUNTIME_MAX_BPS as u128,
        rebate_bps: config.rebate_bps,
        claim_commitment_root: deterministic_root("rebate-claim", &receipt.receipt_id, nonce),
        status: RebateStatus::Claimable,
        opened_at_height: height,
        expires_at_height: height + config.rebate_ttl_blocks,
        nonce: nonce.to_string(),
    }
}
