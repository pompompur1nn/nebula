use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterVoucherRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_PAYMASTER_VOUCHER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-account-abstraction-paymaster-voucher-runtime-v1";
pub const PROTOCOL_VERSION: &str = PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_PAYMASTER_VOUCHER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-aa-paymaster-voucher-public-record-v1";
pub const VOUCHER_BOOK_SUITE: &str = "confidential-aa-paymaster-voucher-book-root-v1";
pub const SEALED_LOT_SUITE: &str = "ml-kem-1024-sealed-paymaster-voucher-lot-root-v1";
pub const SPONSORED_INTENT_SUITE: &str = "zk-sealed-sponsored-account-intent-root-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ml-dsa-87-slh-dsa-paymaster-attestation-root-v1";
pub const REDEMPTION_RECEIPT_SUITE: &str = "account-abstraction-voucher-redemption-receipt-root-v1";
pub const SPENDING_CAP_SUITE: &str = "private-l2-low-fee-paymaster-spending-cap-root-v1";
pub const REBATE_ACCOUNTING_SUITE: &str = "confidential-paymaster-rebate-accounting-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "paymaster-voucher-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "roots-only-paymaster-operator-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_accounts_recipients_amounts_calldata_or_view_keys";
pub const DEVNET_L2_HEIGHT: u64 = 2_730_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_920_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_LOT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_PAYMASTER_FEE_BPS: u64 = 22;
pub const DEFAULT_REBATE_BPS: u64 = 9;
pub const DEFAULT_MIN_ANONYMITY_SET: u64 = 4_096;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 80_000;
pub const DEFAULT_PER_ACCOUNT_CAP_MICRO_UNITS: u64 = 1_000_000;
pub const DEFAULT_PER_LOT_CAP_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_GLOBAL_CAP_MICRO_UNITS: u64 = 250_000_000;
pub const DEFAULT_MAX_GAS_UNITS_PER_INTENT: u64 = 2_000_000;
pub const DEFAULT_MAX_CALLDATA_BYTES: u64 = 8_192;
pub const DEFAULT_OPERATOR_BOND_MICRO_UNITS: u64 = 10_000_000;
pub const MAX_VOUCHER_BOOKS: usize = 262_144;
pub const MAX_SEALED_LOTS: usize = 1_048_576;
pub const MAX_SPONSORED_INTENTS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_RECEIPTS: usize = 2_097_152;
pub const MAX_SPENDING_CAPS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherLane {
    RetailWallet,
    DefiSession,
    BridgeClaim,
    RecoveryFlow,
    ContractSubscription,
    BatchSettlement,
}

impl VoucherLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailWallet => "retail_wallet",
            Self::DefiSession => "defi_session",
            Self::BridgeClaim => "bridge_claim",
            Self::RecoveryFlow => "recovery_flow",
            Self::ContractSubscription => "contract_subscription",
            Self::BatchSettlement => "batch_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCallClass {
    NativeTransfer,
    TokenTransfer,
    Swap,
    Bridge,
    AccountRecovery,
    SessionKeyInstall,
    SubscriptionRenewal,
    CustomCircuit,
}

impl ContractCallClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeTransfer => "native_transfer",
            Self::TokenTransfer => "token_transfer",
            Self::Swap => "swap",
            Self::Bridge => "bridge",
            Self::AccountRecovery => "account_recovery",
            Self::SessionKeyInstall => "session_key_install",
            Self::SubscriptionRenewal => "subscription_renewal",
            Self::CustomCircuit => "custom_circuit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqScheme {
    MlDsa87,
    Falcon1024,
    SlhDsaShake256f,
    MlKem1024,
    HybridLattice,
}

impl PqScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::Falcon1024 => "falcon_1024",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::MlKem1024 => "ml_kem_1024",
            Self::HybridLattice => "hybrid_lattice",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BookStatus {
    Draft,
    Active,
    Paused,
    Draining,
    Exhausted,
    Retired,
}

impl BookStatus {
    pub fn accepts_lots(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Sealed,
    Listed,
    Reserved,
    PartiallyRedeemed,
    Redeemed,
    Expired,
    Quarantined,
}

impl LotStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Listed | Self::Reserved | Self::PartiallyRedeemed
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Listed => "listed",
            Self::Reserved => "reserved",
            Self::PartiallyRedeemed => "partially_redeemed",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    Sponsored,
    Attested,
    Included,
    Redeemed,
    RebateIssued,
    Rejected,
    Expired,
    Quarantined,
}

impl IntentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Admitted | Self::Sponsored | Self::Attested
        )
    }

    pub fn redeemable(self) -> bool {
        matches!(self, Self::Sponsored | Self::Attested | Self::Included)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::Sponsored => "sponsored",
            Self::Attested => "attested",
            Self::Included => "included",
            Self::Redeemed => "redeemed",
            Self::RebateIssued => "rebate_issued",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Challenged,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapWindow {
    Block,
    Hour,
    Day,
    Epoch,
    Lifetime,
}

impl CapWindow {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Epoch => "epoch",
            Self::Lifetime => "lifetime",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Open,
    Active,
    Accepted,
    Settled,
    Exhausted,
    Closed,
    Disputed,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Active => "active",
            Self::Accepted => "accepted",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Closed => "closed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub lot_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_paymaster_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_anonymity_set: u64,
    pub default_redaction_budget_units: u64,
    pub default_per_account_cap_micro_units: u64,
    pub default_per_lot_cap_micro_units: u64,
    pub default_global_cap_micro_units: u64,
    pub max_gas_units_per_intent: u64,
    pub max_calldata_bytes: u64,
    pub operator_bond_micro_units: u64,
    pub privacy_boundary: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            lot_ttl_blocks: DEFAULT_LOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_paymaster_fee_bps: DEFAULT_MAX_PAYMASTER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            default_redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            default_per_account_cap_micro_units: DEFAULT_PER_ACCOUNT_CAP_MICRO_UNITS,
            default_per_lot_cap_micro_units: DEFAULT_PER_LOT_CAP_MICRO_UNITS,
            default_global_cap_micro_units: DEFAULT_GLOBAL_CAP_MICRO_UNITS,
            max_gas_units_per_intent: DEFAULT_MAX_GAS_UNITS_PER_INTENT,
            max_calldata_bytes: DEFAULT_MAX_CALLDATA_BYTES,
            operator_bond_micro_units: DEFAULT_OPERATOR_BOND_MICRO_UNITS,
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version",
        )?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version",
        )?;
        require(self.max_user_fee_bps <= MAX_BPS, "user fee bps too high")?;
        require(
            self.max_paymaster_fee_bps <= MAX_BPS,
            "paymaster fee bps too high",
        )?;
        require(self.rebate_bps <= MAX_BPS, "rebate bps too high")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below floor",
        )?;
        require(self.min_anonymity_set > 0, "anonymity set must be positive")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "public_record_suite": self.public_record_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "lot_ttl_blocks": self.lot_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_paymaster_fee_bps": self.max_paymaster_fee_bps,
            "rebate_bps": self.rebate_bps,
            "min_anonymity_set": self.min_anonymity_set,
            "default_redaction_budget_units": self.default_redaction_budget_units,
            "default_per_account_cap_micro_units": self.default_per_account_cap_micro_units,
            "default_per_lot_cap_micro_units": self.default_per_lot_cap_micro_units,
            "default_global_cap_micro_units": self.default_global_cap_micro_units,
            "max_gas_units_per_intent": self.max_gas_units_per_intent,
            "max_calldata_bytes": self.max_calldata_bytes,
            "operator_bond_micro_units": self.operator_bond_micro_units,
            "privacy_boundary": self.privacy_boundary,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub voucher_books: u64,
    pub active_voucher_books: u64,
    pub sealed_lots: u64,
    pub live_sealed_lots: u64,
    pub sponsored_intents: u64,
    pub live_intents: u64,
    pub pq_attestations: u64,
    pub accepted_attestations: u64,
    pub redemption_receipts: u64,
    pub settled_redemptions: u64,
    pub spending_caps: u64,
    pub exhausted_spending_caps: u64,
    pub rebate_accounts: u64,
    pub pending_rebate_micro_units: u64,
    pub paid_rebate_micro_units: u64,
    pub redaction_budgets: u64,
    pub exhausted_redaction_budgets: u64,
    pub operator_summaries: u64,
    pub deterministic_public_records: u64,
    pub sponsored_gas_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub redaction_units_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub voucher_books_root: String,
    pub sealed_lots_root: String,
    pub sponsored_intents_root: String,
    pub pq_attestations_root: String,
    pub redemption_receipts_root: String,
    pub spending_caps_root: String,
    pub rebate_accounting_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub spent_nullifiers_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VoucherBook {
    pub book_id: String,
    pub paymaster_commitment: String,
    pub operator_id: String,
    pub lane: VoucherLane,
    pub status: BookStatus,
    pub settlement_contract_commitment: String,
    pub accepted_call_classes: BTreeSet<ContractCallClass>,
    pub voucher_denomination_micro_units: u64,
    pub prepaid_liquidity_micro_units: u64,
    pub reserved_liquidity_micro_units: u64,
    pub redeemed_liquidity_micro_units: u64,
    pub rebate_pool_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub max_paymaster_fee_bps: u64,
    pub min_anonymity_set: u64,
    pub pq_scheme: PqScheme,
    pub pq_security_bits: u16,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub metadata_commitment: String,
}

impl VoucherBook {
    pub fn new(
        book_id: &str,
        operator_id: &str,
        lane: VoucherLane,
        class: ContractCallClass,
        liquidity: u64,
    ) -> Self {
        let mut accepted_call_classes = BTreeSet::new();
        accepted_call_classes.insert(class);
        Self {
            book_id: book_id.to_string(),
            paymaster_commitment: deterministic_id("paymaster", &[book_id, operator_id]),
            operator_id: operator_id.to_string(),
            lane,
            status: BookStatus::Active,
            settlement_contract_commitment: deterministic_id(
                "contract",
                &[book_id, class.as_str()],
            ),
            accepted_call_classes,
            voucher_denomination_micro_units: 10_000,
            prepaid_liquidity_micro_units: liquidity,
            reserved_liquidity_micro_units: 0,
            redeemed_liquidity_micro_units: 0,
            rebate_pool_micro_units: liquidity / 100,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_paymaster_fee_bps: DEFAULT_MAX_PAYMASTER_FEE_BPS,
            min_anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            pq_scheme: PqScheme::MlDsa87,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            opened_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_VOUCHER_TTL_BLOCKS,
            metadata_commitment: deterministic_id("book-meta", &[book_id, operator_id]),
        }
    }

    pub fn available_liquidity(&self) -> u64 {
        self.prepaid_liquidity_micro_units.saturating_sub(
            self.reserved_liquidity_micro_units + self.redeemed_liquidity_micro_units,
        )
    }

    pub fn reserve(&mut self, micro_units: u64) -> Result<()> {
        require(
            self.status.accepts_lots(),
            "voucher book is not accepting lots",
        )?;
        require(
            self.available_liquidity() >= micro_units,
            "insufficient voucher book liquidity",
        )?;
        self.reserved_liquidity_micro_units += micro_units;
        Ok(())
    }

    pub fn redeem_reserved(&mut self, micro_units: u64) -> Result<()> {
        require(
            self.reserved_liquidity_micro_units >= micro_units,
            "reserved liquidity underflow",
        )?;
        self.reserved_liquidity_micro_units -= micro_units;
        self.redeemed_liquidity_micro_units += micro_units;
        if self.available_liquidity() == 0 && self.reserved_liquidity_micro_units == 0 {
            self.status = BookStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "paymaster_commitment": self.paymaster_commitment,
            "operator_id": self.operator_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "settlement_contract_commitment": self.settlement_contract_commitment,
            "accepted_call_classes": self.accepted_call_classes.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            "voucher_denomination_micro_units": self.voucher_denomination_micro_units,
            "prepaid_liquidity_micro_units": self.prepaid_liquidity_micro_units,
            "reserved_liquidity_micro_units": self.reserved_liquidity_micro_units,
            "redeemed_liquidity_micro_units": self.redeemed_liquidity_micro_units,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_paymaster_fee_bps": self.max_paymaster_fee_bps,
            "min_anonymity_set": self.min_anonymity_set,
            "pq_scheme": self.pq_scheme.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "opened_l2_height": self.opened_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "metadata_commitment": self.metadata_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedVoucherLot {
    pub lot_id: String,
    pub book_id: String,
    pub status: LotStatus,
    pub lane: VoucherLane,
    pub sealed_voucher_root: String,
    pub nullifier_root: String,
    pub encrypted_payload_root: String,
    pub voucher_count: u64,
    pub reserved_count: u64,
    pub redeemed_count: u64,
    pub face_value_micro_units: u64,
    pub max_total_fee_micro_units: u64,
    pub anonymity_set_size: u64,
    pub low_fee_floor_micro_units: u64,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
}

impl SealedVoucherLot {
    pub fn new(
        lot_id: &str,
        book_id: &str,
        lane: VoucherLane,
        count: u64,
        face_value: u64,
    ) -> Self {
        Self {
            lot_id: lot_id.to_string(),
            book_id: book_id.to_string(),
            status: LotStatus::Listed,
            lane,
            sealed_voucher_root: deterministic_id("sealed-voucher-root", &[lot_id, book_id]),
            nullifier_root: deterministic_id("voucher-nullifier-root", &[lot_id, book_id]),
            encrypted_payload_root: deterministic_id("voucher-payload-root", &[lot_id, book_id]),
            voucher_count: count,
            reserved_count: 0,
            redeemed_count: 0,
            face_value_micro_units: face_value,
            max_total_fee_micro_units: face_value * count,
            anonymity_set_size: DEFAULT_MIN_ANONYMITY_SET,
            low_fee_floor_micro_units: 500,
            opened_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_LOT_TTL_BLOCKS,
        }
    }

    pub fn available_count(&self) -> u64 {
        self.voucher_count
            .saturating_sub(self.reserved_count + self.redeemed_count)
    }

    pub fn reserve_one(&mut self) -> Result<()> {
        require(self.status.live(), "voucher lot is not live")?;
        require(self.available_count() > 0, "voucher lot exhausted")?;
        self.reserved_count += 1;
        self.status = LotStatus::Reserved;
        Ok(())
    }

    pub fn redeem_one(&mut self) -> Result<()> {
        require(self.reserved_count > 0, "no reserved voucher to redeem")?;
        self.reserved_count -= 1;
        self.redeemed_count += 1;
        self.status = if self.redeemed_count == self.voucher_count {
            LotStatus::Redeemed
        } else {
            LotStatus::PartiallyRedeemed
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "book_id": self.book_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "sealed_voucher_root": self.sealed_voucher_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "voucher_count": self.voucher_count,
            "reserved_count": self.reserved_count,
            "redeemed_count": self.redeemed_count,
            "face_value_micro_units": self.face_value_micro_units,
            "max_total_fee_micro_units": self.max_total_fee_micro_units,
            "anonymity_set_size": self.anonymity_set_size,
            "low_fee_floor_micro_units": self.low_fee_floor_micro_units,
            "opened_l2_height": self.opened_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsoredAccountIntent {
    pub intent_id: String,
    pub account_commitment: String,
    pub book_id: String,
    pub lot_id: String,
    pub class: ContractCallClass,
    pub status: IntentStatus,
    pub sealed_user_operation_root: String,
    pub calldata_commitment: String,
    pub spending_cap_id: String,
    pub max_gas_units: u64,
    pub max_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}

impl SponsoredAccountIntent {
    pub fn new(
        intent_id: &str,
        book_id: &str,
        lot_id: &str,
        class: ContractCallClass,
        cap_id: &str,
    ) -> Self {
        Self {
            intent_id: intent_id.to_string(),
            account_commitment: deterministic_id("aa-account", &[intent_id]),
            book_id: book_id.to_string(),
            lot_id: lot_id.to_string(),
            class,
            status: IntentStatus::Admitted,
            sealed_user_operation_root: deterministic_id("sealed-user-op", &[intent_id, book_id]),
            calldata_commitment: deterministic_id("calldata", &[intent_id, class.as_str()]),
            spending_cap_id: cap_id.to_string(),
            max_gas_units: 240_000,
            max_fee_micro_units: 8_000,
            user_fee_micro_units: 900,
            privacy_set_size: DEFAULT_MIN_ANONYMITY_SET,
            created_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_INTENT_TTL_BLOCKS,
        }
    }

    pub fn sponsor(&mut self) -> Result<()> {
        require(
            matches!(self.status, IntentStatus::Admitted | IntentStatus::Sealed),
            "intent cannot be sponsored",
        )?;
        self.status = IntentStatus::Sponsored;
        Ok(())
    }

    pub fn mark_attested(&mut self) -> Result<()> {
        require(
            self.status == IntentStatus::Sponsored,
            "intent must be sponsored before attestation",
        )?;
        self.status = IntentStatus::Attested;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "account_commitment": self.account_commitment,
            "book_id": self.book_id,
            "lot_id": self.lot_id,
            "class": self.class.as_str(),
            "status": self.status.as_str(),
            "sealed_user_operation_root": self.sealed_user_operation_root,
            "calldata_commitment": self.calldata_commitment,
            "spending_cap_id": self.spending_cap_id,
            "max_gas_units": self.max_gas_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "user_fee_micro_units": self.user_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqPaymasterAttestation {
    pub attestation_id: String,
    pub intent_id: String,
    pub book_id: String,
    pub operator_id: String,
    pub scheme: PqScheme,
    pub status: AttestationStatus,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub sponsored_fee_micro_units: u64,
    pub attested_gas_units: u64,
    pub security_bits: u16,
    pub issued_l2_height: u64,
    pub expires_l2_height: u64,
}

impl PqPaymasterAttestation {
    pub fn new(
        attestation_id: &str,
        intent_id: &str,
        book_id: &str,
        operator_id: &str,
        fee: u64,
        gas: u64,
    ) -> Self {
        Self {
            attestation_id: attestation_id.to_string(),
            intent_id: intent_id.to_string(),
            book_id: book_id.to_string(),
            operator_id: operator_id.to_string(),
            scheme: PqScheme::MlDsa87,
            status: AttestationStatus::Accepted,
            public_key_commitment: deterministic_id("pq-paymaster-pk", &[operator_id, book_id]),
            signature_commitment: deterministic_id(
                "pq-paymaster-sig",
                &[attestation_id, intent_id],
            ),
            transcript_root: deterministic_id(
                "pq-paymaster-transcript",
                &[attestation_id, intent_id, book_id],
            ),
            sponsored_fee_micro_units: fee,
            attested_gas_units: gas,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            issued_l2_height: DEVNET_L2_HEIGHT + 1,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "intent_id": self.intent_id,
            "book_id": self.book_id,
            "operator_id": self.operator_id,
            "scheme": self.scheme.as_str(),
            "status": self.status.as_str(),
            "public_key_commitment": self.public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "attested_gas_units": self.attested_gas_units,
            "security_bits": self.security_bits,
            "issued_l2_height": self.issued_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedemptionReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub lot_id: String,
    pub book_id: String,
    pub voucher_nullifier: String,
    pub user_operation_hash: String,
    pub receipt_root: String,
    pub status: RecordStatus,
    pub gas_used: u64,
    pub fee_paid_micro_units: u64,
    pub paymaster_refund_micro_units: u64,
    pub rebate_micro_units: u64,
    pub settled_l2_height: u64,
}

impl RedemptionReceipt {
    pub fn new(
        receipt_id: &str,
        intent_id: &str,
        lot_id: &str,
        book_id: &str,
        fee: u64,
        gas: u64,
    ) -> Self {
        let rebate = fee.saturating_mul(DEFAULT_REBATE_BPS) / MAX_BPS;
        Self {
            receipt_id: receipt_id.to_string(),
            intent_id: intent_id.to_string(),
            lot_id: lot_id.to_string(),
            book_id: book_id.to_string(),
            voucher_nullifier: deterministic_id("voucher-nullifier", &[receipt_id, intent_id]),
            user_operation_hash: deterministic_id("user-op-hash", &[intent_id, book_id]),
            receipt_root: deterministic_id("redemption-receipt", &[receipt_id, intent_id, lot_id]),
            status: RecordStatus::Settled,
            gas_used: gas,
            fee_paid_micro_units: fee,
            paymaster_refund_micro_units: fee / 20,
            rebate_micro_units: rebate,
            settled_l2_height: DEVNET_L2_HEIGHT + 3,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "lot_id": self.lot_id,
            "book_id": self.book_id,
            "voucher_nullifier": self.voucher_nullifier,
            "user_operation_hash": self.user_operation_hash,
            "receipt_root": self.receipt_root,
            "status": self.status.as_str(),
            "gas_used": self.gas_used,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "paymaster_refund_micro_units": self.paymaster_refund_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "settled_l2_height": self.settled_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SpendingCap {
    pub cap_id: String,
    pub book_id: String,
    pub account_scope_commitment: String,
    pub contract_scope_commitment: String,
    pub window: CapWindow,
    pub status: RecordStatus,
    pub cap_micro_units: u64,
    pub consumed_micro_units: u64,
    pub max_gas_units: u64,
    pub consumed_gas_units: u64,
    pub reset_l2_height: u64,
}

impl SpendingCap {
    pub fn new(cap_id: &str, book_id: &str, window: CapWindow, cap: u64) -> Self {
        Self {
            cap_id: cap_id.to_string(),
            book_id: book_id.to_string(),
            account_scope_commitment: deterministic_id("cap-account-scope", &[cap_id, book_id]),
            contract_scope_commitment: deterministic_id("cap-contract-scope", &[cap_id, book_id]),
            window,
            status: RecordStatus::Active,
            cap_micro_units: cap,
            consumed_micro_units: 0,
            max_gas_units: DEFAULT_MAX_GAS_UNITS_PER_INTENT * 8,
            consumed_gas_units: 0,
            reset_l2_height: DEVNET_L2_HEIGHT + 7_200,
        }
    }

    pub fn remaining_micro_units(&self) -> u64 {
        self.cap_micro_units
            .saturating_sub(self.consumed_micro_units)
    }

    pub fn consume(&mut self, fee: u64, gas: u64) -> Result<()> {
        require(
            self.remaining_micro_units() >= fee,
            "spending cap fee exceeded",
        )?;
        require(
            self.max_gas_units.saturating_sub(self.consumed_gas_units) >= gas,
            "spending cap gas exceeded",
        )?;
        self.consumed_micro_units += fee;
        self.consumed_gas_units += gas;
        if self.remaining_micro_units() == 0 {
            self.status = RecordStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "book_id": self.book_id,
            "account_scope_commitment": self.account_scope_commitment,
            "contract_scope_commitment": self.contract_scope_commitment,
            "window": self.window.as_str(),
            "status": self.status.as_str(),
            "cap_micro_units": self.cap_micro_units,
            "consumed_micro_units": self.consumed_micro_units,
            "remaining_micro_units": self.remaining_micro_units(),
            "max_gas_units": self.max_gas_units,
            "consumed_gas_units": self.consumed_gas_units,
            "reset_l2_height": self.reset_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateAccounting {
    pub rebate_id: String,
    pub book_id: String,
    pub operator_id: String,
    pub status: RecordStatus,
    pub accrued_micro_units: u64,
    pub paid_micro_units: u64,
    pub clawed_back_micro_units: u64,
    pub low_fee_savings_micro_units: u64,
    pub settlement_root: String,
}

impl RebateAccounting {
    pub fn new(rebate_id: &str, book_id: &str, operator_id: &str) -> Self {
        Self {
            rebate_id: rebate_id.to_string(),
            book_id: book_id.to_string(),
            operator_id: operator_id.to_string(),
            status: RecordStatus::Open,
            accrued_micro_units: 0,
            paid_micro_units: 0,
            clawed_back_micro_units: 0,
            low_fee_savings_micro_units: 0,
            settlement_root: deterministic_id("rebate-settlement", &[rebate_id, book_id]),
        }
    }

    pub fn accrue(&mut self, rebate: u64, savings: u64) {
        self.accrued_micro_units += rebate;
        self.low_fee_savings_micro_units += savings;
    }

    pub fn pay(&mut self, amount: u64) -> Result<()> {
        require(
            self.pending_micro_units() >= amount,
            "rebate payment exceeds pending balance",
        )?;
        self.paid_micro_units += amount;
        if self.accrued_micro_units == self.paid_micro_units + self.clawed_back_micro_units {
            self.status = RecordStatus::Settled;
        }
        Ok(())
    }

    pub fn pending_micro_units(&self) -> u64 {
        self.accrued_micro_units
            .saturating_sub(self.paid_micro_units + self.clawed_back_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "book_id": self.book_id,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "accrued_micro_units": self.accrued_micro_units,
            "paid_micro_units": self.paid_micro_units,
            "pending_micro_units": self.pending_micro_units(),
            "clawed_back_micro_units": self.clawed_back_micro_units,
            "low_fee_savings_micro_units": self.low_fee_savings_micro_units,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub scope: String,
    pub status: RecordStatus,
    pub total_units: u64,
    pub consumed_units: u64,
    pub disclosure_root: String,
}

impl RedactionBudget {
    pub fn new(budget_id: &str, scope: &str, units: u64) -> Self {
        Self {
            budget_id: budget_id.to_string(),
            owner_commitment: deterministic_id("redaction-owner", &[budget_id, scope]),
            scope: scope.to_string(),
            status: RecordStatus::Active,
            total_units: units,
            consumed_units: 0,
            disclosure_root: deterministic_id("redaction-disclosure", &[budget_id, scope]),
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.consumed_units)
    }

    pub fn consume(&mut self, units: u64) -> Result<()> {
        require(self.remaining_units() >= units, "redaction budget exceeded")?;
        self.consumed_units += units;
        if self.remaining_units() == 0 {
            self.status = RecordStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "scope": self.scope,
            "status": self.status.as_str(),
            "total_units": self.total_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units(),
            "disclosure_root": self.disclosure_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub status: RecordStatus,
    pub paymaster_commitment_root: String,
    pub active_books: u64,
    pub live_lots: u64,
    pub accepted_attestations: u64,
    pub settled_receipts: u64,
    pub sponsored_fee_micro_units: u64,
    pub paid_rebate_micro_units: u64,
    pub bond_micro_units: u64,
    pub slash_count: u64,
    pub last_l2_height: u64,
}

impl OperatorSummary {
    pub fn new(operator_id: &str) -> Self {
        Self {
            operator_id: operator_id.to_string(),
            status: RecordStatus::Active,
            paymaster_commitment_root: deterministic_id("operator-paymasters", &[operator_id]),
            active_books: 0,
            live_lots: 0,
            accepted_attestations: 0,
            settled_receipts: 0,
            sponsored_fee_micro_units: 0,
            paid_rebate_micro_units: 0,
            bond_micro_units: DEFAULT_OPERATOR_BOND_MICRO_UNITS,
            slash_count: 0,
            last_l2_height: DEVNET_L2_HEIGHT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "paymaster_commitment_root": self.paymaster_commitment_root,
            "active_books": self.active_books,
            "live_lots": self.live_lots,
            "accepted_attestations": self.accepted_attestations,
            "settled_receipts": self.settled_receipts,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "paid_rebate_micro_units": self.paid_rebate_micro_units,
            "bond_micro_units": self.bond_micro_units,
            "slash_count": self.slash_count,
            "last_l2_height": self.last_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub suite: String,
    pub record_root: String,
    pub l2_height: u64,
    pub payload: Value,
}

impl PublicRecord {
    pub fn new(record_id: &str, suite: &str, payload: Value) -> Self {
        let record_root = record_root("PUBLIC-RECORD", &payload);
        Self {
            record_id: record_id.to_string(),
            suite: suite.to_string(),
            record_root,
            l2_height: DEVNET_L2_HEIGHT,
            payload,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "suite": self.suite,
            "record_root": self.record_root,
            "l2_height": self.l2_height,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub voucher_books: BTreeMap<String, VoucherBook>,
    pub sealed_lots: BTreeMap<String, SealedVoucherLot>,
    pub sponsored_intents: BTreeMap<String, SponsoredAccountIntent>,
    pub pq_attestations: BTreeMap<String, PqPaymasterAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub spending_caps: BTreeMap<String, SpendingCap>,
    pub rebate_accounting: BTreeMap<String, RebateAccounting>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub spent_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRecord>,
}

impl State {
    pub fn empty(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            voucher_books: BTreeMap::new(),
            sealed_lots: BTreeMap::new(),
            sponsored_intents: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            spending_caps: BTreeMap::new(),
            rebate_accounting: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::empty(Config::devnet());
        let operator = "operator-devnet-paymaster-alpha";
        state
            .insert_operator_summary(OperatorSummary::new(operator))
            .expect("devnet operator summary");
        state
            .insert_voucher_book(VoucherBook::new(
                "book-retail-low-fee",
                operator,
                VoucherLane::RetailWallet,
                ContractCallClass::TokenTransfer,
                50_000_000,
            ))
            .expect("devnet voucher book");
        state
            .insert_voucher_book(VoucherBook::new(
                "book-defi-session",
                operator,
                VoucherLane::DefiSession,
                ContractCallClass::Swap,
                80_000_000,
            ))
            .expect("devnet voucher book");
        state
            .insert_sealed_lot(SealedVoucherLot::new(
                "lot-retail-0001",
                "book-retail-low-fee",
                VoucherLane::RetailWallet,
                512,
                10_000,
            ))
            .expect("devnet lot");
        state
            .insert_sealed_lot(SealedVoucherLot::new(
                "lot-defi-0001",
                "book-defi-session",
                VoucherLane::DefiSession,
                256,
                20_000,
            ))
            .expect("devnet lot");
        state
            .insert_spending_cap(SpendingCap::new(
                "cap-retail-daily",
                "book-retail-low-fee",
                CapWindow::Day,
                DEFAULT_PER_ACCOUNT_CAP_MICRO_UNITS,
            ))
            .expect("devnet cap");
        state
            .insert_spending_cap(SpendingCap::new(
                "cap-defi-epoch",
                "book-defi-session",
                CapWindow::Epoch,
                DEFAULT_PER_LOT_CAP_MICRO_UNITS,
            ))
            .expect("devnet cap");
        state
            .insert_rebate_accounting(RebateAccounting::new(
                "rebate-retail",
                "book-retail-low-fee",
                operator,
            ))
            .expect("devnet rebate");
        state
            .insert_rebate_accounting(RebateAccounting::new(
                "rebate-defi",
                "book-defi-session",
                operator,
            ))
            .expect("devnet rebate");
        state
            .insert_redaction_budget(RedactionBudget::new(
                "redaction-retail",
                "retail voucher disclosures",
                DEFAULT_REDACTION_BUDGET_UNITS,
            ))
            .expect("devnet redaction budget");
        state
            .insert_redaction_budget(RedactionBudget::new(
                "redaction-defi",
                "defi session disclosures",
                DEFAULT_REDACTION_BUDGET_UNITS,
            ))
            .expect("devnet redaction budget");
        state.refresh();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state
            .sponsor_intent(SponsoredAccountIntent::new(
                "intent-retail-transfer-0001",
                "book-retail-low-fee",
                "lot-retail-0001",
                ContractCallClass::TokenTransfer,
                "cap-retail-daily",
            ))
            .expect("demo intent");
        state
            .attach_attestation(PqPaymasterAttestation::new(
                "attestation-retail-0001",
                "intent-retail-transfer-0001",
                "book-retail-low-fee",
                "operator-devnet-paymaster-alpha",
                7_800,
                218_000,
            ))
            .expect("demo attestation");
        state
            .redeem_intent("receipt-retail-0001", "intent-retail-transfer-0001")
            .expect("demo redemption");
        state
            .consume_redaction_budget("redaction-retail", 1_250)
            .expect("demo redaction");
        state
            .insert_public_record(PublicRecord::new(
                "public-record-demo",
                PUBLIC_RECORD_SUITE,
                state.public_record(),
            ))
            .expect("demo public record");
        state.refresh();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "voucher_books": map_records(&self.voucher_books, VoucherBook::public_record),
            "sealed_lots": map_records(&self.sealed_lots, SealedVoucherLot::public_record),
            "sponsored_intents": map_records(&self.sponsored_intents, SponsoredAccountIntent::public_record),
            "pq_attestations": map_records(&self.pq_attestations, PqPaymasterAttestation::public_record),
            "redemption_receipts": map_records(&self.redemption_receipts, RedemptionReceipt::public_record),
            "spending_caps": map_records(&self.spending_caps, SpendingCap::public_record),
            "rebate_accounting": map_records(&self.rebate_accounting, RebateAccounting::public_record),
            "redaction_budgets": map_records(&self.redaction_budgets, RedactionBudget::public_record),
            "operator_summaries": map_records(&self.operator_summaries, OperatorSummary::public_record),
            "spent_nullifiers_root": set_root("SPENT-NULLIFIERS", &self.spent_nullifiers),
            "public_records": map_records(&self.public_records, PublicRecord::public_record),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "STATE",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "counters": self.counters.public_record(),
                "roots": {
                    "config_root": self.roots.config_root,
                    "voucher_books_root": self.roots.voucher_books_root,
                    "sealed_lots_root": self.roots.sealed_lots_root,
                    "sponsored_intents_root": self.roots.sponsored_intents_root,
                    "pq_attestations_root": self.roots.pq_attestations_root,
                    "redemption_receipts_root": self.roots.redemption_receipts_root,
                    "spending_caps_root": self.roots.spending_caps_root,
                    "rebate_accounting_root": self.roots.rebate_accounting_root,
                    "redaction_budgets_root": self.roots.redaction_budgets_root,
                    "operator_summaries_root": self.roots.operator_summaries_root,
                    "spent_nullifiers_root": self.roots.spent_nullifiers_root,
                    "public_records_root": self.roots.public_records_root,
                }
            }),
        )
    }

    pub fn insert_voucher_book(&mut self, book: VoucherBook) -> Result<()> {
        require(
            self.voucher_books.len() < MAX_VOUCHER_BOOKS,
            "too many voucher books",
        )?;
        require(
            book.pq_security_bits >= self.config.min_pq_security_bits,
            "voucher book pq security below floor",
        )?;
        self.voucher_books.insert(book.book_id.clone(), book);
        self.refresh();
        Ok(())
    }

    pub fn insert_sealed_lot(&mut self, lot: SealedVoucherLot) -> Result<()> {
        require(
            self.sealed_lots.len() < MAX_SEALED_LOTS,
            "too many sealed voucher lots",
        )?;
        let book = self
            .voucher_books
            .get_mut(&lot.book_id)
            .ok_or_else(|| "missing voucher book".to_string())?;
        require(
            book.min_anonymity_set <= lot.anonymity_set_size,
            "voucher lot anonymity set below book floor",
        )?;
        book.reserve(lot.max_total_fee_micro_units)?;
        self.sealed_lots.insert(lot.lot_id.clone(), lot);
        self.refresh();
        Ok(())
    }

    pub fn sponsor_intent(&mut self, mut intent: SponsoredAccountIntent) -> Result<()> {
        require(
            self.sponsored_intents.len() < MAX_SPONSORED_INTENTS,
            "too many sponsored intents",
        )?;
        require(
            intent.max_gas_units <= self.config.max_gas_units_per_intent,
            "intent gas above configured ceiling",
        )?;
        let book = self
            .voucher_books
            .get(&intent.book_id)
            .ok_or_else(|| "missing voucher book".to_string())?;
        require(
            book.accepted_call_classes.contains(&intent.class),
            "intent call class not accepted by voucher book",
        )?;
        let lot = self
            .sealed_lots
            .get_mut(&intent.lot_id)
            .ok_or_else(|| "missing voucher lot".to_string())?;
        let cap = self
            .spending_caps
            .get_mut(&intent.spending_cap_id)
            .ok_or_else(|| "missing spending cap".to_string())?;
        lot.reserve_one()?;
        cap.consume(intent.max_fee_micro_units, intent.max_gas_units)?;
        intent.sponsor()?;
        self.sponsored_intents
            .insert(intent.intent_id.clone(), intent);
        self.refresh();
        Ok(())
    }

    pub fn attach_attestation(&mut self, attestation: PqPaymasterAttestation) -> Result<()> {
        require(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "too many pq attestations",
        )?;
        require(
            attestation.security_bits >= self.config.min_pq_security_bits,
            "attestation pq security below floor",
        )?;
        let intent = self
            .sponsored_intents
            .get_mut(&attestation.intent_id)
            .ok_or_else(|| "missing sponsored intent".to_string())?;
        require(
            intent.book_id == attestation.book_id,
            "attestation book mismatch",
        )?;
        intent.mark_attested()?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh();
        Ok(())
    }

    pub fn redeem_intent(&mut self, receipt_id: &str, intent_id: &str) -> Result<()> {
        require(
            self.redemption_receipts.len() < MAX_RECEIPTS,
            "too many redemption receipts",
        )?;
        let intent = self
            .sponsored_intents
            .get_mut(intent_id)
            .ok_or_else(|| "missing sponsored intent".to_string())?;
        require(intent.status.redeemable(), "intent is not redeemable")?;
        let lot = self
            .sealed_lots
            .get_mut(&intent.lot_id)
            .ok_or_else(|| "missing voucher lot".to_string())?;
        let book = self
            .voucher_books
            .get_mut(&intent.book_id)
            .ok_or_else(|| "missing voucher book".to_string())?;
        let receipt = RedemptionReceipt::new(
            receipt_id,
            intent_id,
            &intent.lot_id,
            &intent.book_id,
            intent.max_fee_micro_units,
            intent.max_gas_units,
        );
        require(
            !self.spent_nullifiers.contains(&receipt.voucher_nullifier),
            "voucher nullifier already spent",
        )?;
        lot.redeem_one()?;
        book.redeem_reserved(intent.max_fee_micro_units)?;
        intent.status = IntentStatus::Redeemed;
        self.spent_nullifiers
            .insert(receipt.voucher_nullifier.clone());
        if let Some(rebate) = self
            .rebate_accounting
            .values_mut()
            .find(|rebate| rebate.book_id == intent.book_id)
        {
            rebate.accrue(
                receipt.rebate_micro_units,
                receipt.paymaster_refund_micro_units,
            );
            let pending = rebate.pending_micro_units();
            rebate.pay(pending)?;
        }
        self.redemption_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.refresh();
        Ok(())
    }

    pub fn consume_redaction_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "missing redaction budget".to_string())?;
        budget.consume(units)?;
        self.refresh();
        Ok(())
    }

    pub fn insert_spending_cap(&mut self, cap: SpendingCap) -> Result<()> {
        require(
            self.spending_caps.len() < MAX_SPENDING_CAPS,
            "too many spending caps",
        )?;
        self.spending_caps.insert(cap.cap_id.clone(), cap);
        self.refresh();
        Ok(())
    }

    pub fn insert_rebate_accounting(&mut self, rebate: RebateAccounting) -> Result<()> {
        require(
            self.rebate_accounting.len() < MAX_REBATES,
            "too many rebate accounts",
        )?;
        self.rebate_accounting
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        require(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "too many redaction budgets",
        )?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh();
        Ok(())
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        require(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "too many operator summaries",
        )?;
        self.operator_summaries
            .insert(summary.operator_id.clone(), summary);
        self.refresh();
        Ok(())
    }

    pub fn insert_public_record(&mut self, public_record: PublicRecord) -> Result<()> {
        require(
            self.public_records.len() < MAX_PUBLIC_RECORDS,
            "too many public records",
        )?;
        self.public_records
            .insert(public_record.record_id.clone(), public_record);
        self.refresh();
        Ok(())
    }

    pub fn refresh(&mut self) {
        self.config.validate().expect("valid runtime config");
        self.refresh_operator_summaries();
        self.refresh_counters();
        self.refresh_roots();
    }

    fn refresh_operator_summaries(&mut self) {
        for summary in self.operator_summaries.values_mut() {
            summary.active_books = self
                .voucher_books
                .values()
                .filter(|book| {
                    book.operator_id == summary.operator_id && book.status.accepts_lots()
                })
                .count() as u64;
            summary.live_lots = self
                .sealed_lots
                .values()
                .filter(|lot| {
                    lot.status.live()
                        && self
                            .voucher_books
                            .get(&lot.book_id)
                            .map(|book| book.operator_id.as_str())
                            == Some(summary.operator_id.as_str())
                })
                .count() as u64;
            summary.accepted_attestations = self
                .pq_attestations
                .values()
                .filter(|attestation| {
                    attestation.operator_id == summary.operator_id && attestation.status.accepted()
                })
                .count() as u64;
            summary.settled_receipts = self
                .redemption_receipts
                .values()
                .filter(|receipt| {
                    self.voucher_books
                        .get(&receipt.book_id)
                        .map(|book| book.operator_id.as_str())
                        == Some(summary.operator_id.as_str())
                        && receipt.status == RecordStatus::Settled
                })
                .count() as u64;
            summary.sponsored_fee_micro_units = self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.operator_id == summary.operator_id)
                .map(|attestation| attestation.sponsored_fee_micro_units)
                .sum();
            summary.paid_rebate_micro_units = self
                .rebate_accounting
                .values()
                .filter(|rebate| rebate.operator_id == summary.operator_id)
                .map(|rebate| rebate.paid_micro_units)
                .sum();
            summary.last_l2_height = DEVNET_L2_HEIGHT + summary.settled_receipts;
        }
    }

    fn refresh_counters(&mut self) {
        self.counters = Counters {
            voucher_books: self.voucher_books.len() as u64,
            active_voucher_books: self
                .voucher_books
                .values()
                .filter(|book| book.status.accepts_lots())
                .count() as u64,
            sealed_lots: self.sealed_lots.len() as u64,
            live_sealed_lots: self
                .sealed_lots
                .values()
                .filter(|lot| lot.status.live())
                .count() as u64,
            sponsored_intents: self.sponsored_intents.len() as u64,
            live_intents: self
                .sponsored_intents
                .values()
                .filter(|intent| intent.status.live())
                .count() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            accepted_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.accepted())
                .count() as u64,
            redemption_receipts: self.redemption_receipts.len() as u64,
            settled_redemptions: self
                .redemption_receipts
                .values()
                .filter(|receipt| receipt.status == RecordStatus::Settled)
                .count() as u64,
            spending_caps: self.spending_caps.len() as u64,
            exhausted_spending_caps: self
                .spending_caps
                .values()
                .filter(|cap| cap.status == RecordStatus::Exhausted)
                .count() as u64,
            rebate_accounts: self.rebate_accounting.len() as u64,
            pending_rebate_micro_units: self
                .rebate_accounting
                .values()
                .map(RebateAccounting::pending_micro_units)
                .sum(),
            paid_rebate_micro_units: self
                .rebate_accounting
                .values()
                .map(|rebate| rebate.paid_micro_units)
                .sum(),
            redaction_budgets: self.redaction_budgets.len() as u64,
            exhausted_redaction_budgets: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.status == RecordStatus::Exhausted)
                .count() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            deterministic_public_records: self.public_records.len() as u64,
            sponsored_gas_units: self
                .pq_attestations
                .values()
                .map(|attestation| attestation.attested_gas_units)
                .sum(),
            sponsored_fee_micro_units: self
                .pq_attestations
                .values()
                .map(|attestation| attestation.sponsored_fee_micro_units)
                .sum(),
            redaction_units_consumed: self
                .redaction_budgets
                .values()
                .map(|budget| budget.consumed_units)
                .sum(),
        };
    }

    fn refresh_roots(&mut self) {
        let config_root = record_root("CONFIG", &self.config.public_record());
        let voucher_books_root = map_root(
            "VOUCHER-BOOKS",
            &self.voucher_books,
            VoucherBook::public_record,
        );
        let sealed_lots_root = map_root(
            "SEALED-LOTS",
            &self.sealed_lots,
            SealedVoucherLot::public_record,
        );
        let sponsored_intents_root = map_root(
            "SPONSORED-INTENTS",
            &self.sponsored_intents,
            SponsoredAccountIntent::public_record,
        );
        let pq_attestations_root = map_root(
            "PQ-ATTESTATIONS",
            &self.pq_attestations,
            PqPaymasterAttestation::public_record,
        );
        let redemption_receipts_root = map_root(
            "REDEMPTION-RECEIPTS",
            &self.redemption_receipts,
            RedemptionReceipt::public_record,
        );
        let spending_caps_root = map_root(
            "SPENDING-CAPS",
            &self.spending_caps,
            SpendingCap::public_record,
        );
        let rebate_accounting_root = map_root(
            "REBATE-ACCOUNTING",
            &self.rebate_accounting,
            RebateAccounting::public_record,
        );
        let redaction_budgets_root = map_root(
            "REDACTION-BUDGETS",
            &self.redaction_budgets,
            RedactionBudget::public_record,
        );
        let operator_summaries_root = map_root(
            "OPERATOR-SUMMARIES",
            &self.operator_summaries,
            OperatorSummary::public_record,
        );
        let spent_nullifiers_root = set_root("SPENT-NULLIFIERS", &self.spent_nullifiers);
        let public_records_root = map_root(
            "PUBLIC-RECORDS",
            &self.public_records,
            PublicRecord::public_record,
        );
        let state_root = record_root(
            "STATE-ROOT",
            &json!({
                "config_root": config_root,
                "voucher_books_root": voucher_books_root,
                "sealed_lots_root": sealed_lots_root,
                "sponsored_intents_root": sponsored_intents_root,
                "pq_attestations_root": pq_attestations_root,
                "redemption_receipts_root": redemption_receipts_root,
                "spending_caps_root": spending_caps_root,
                "rebate_accounting_root": rebate_accounting_root,
                "redaction_budgets_root": redaction_budgets_root,
                "operator_summaries_root": operator_summaries_root,
                "spent_nullifiers_root": spent_nullifiers_root,
                "public_records_root": public_records_root,
            }),
        );
        self.roots = Roots {
            config_root,
            voucher_books_root,
            sealed_lots_root,
            sponsored_intents_root,
            pq_attestations_root,
            redemption_receipts_root,
            spending_caps_root,
            rebate_accounting_root,
            redaction_budgets_root,
            operator_summaries_root,
            spent_nullifiers_root,
            public_records_root,
            state_root,
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn fixed_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-AA-PAYMASTER-VOUCHER-FIXED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let root = domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-AA-PAYMASTER-VOUCHER-ID",
        &[HashPart::Str(prefix), HashPart::Json(&json!(parts))],
        16,
    );
    format!("{prefix}-{root}")
}

pub fn map_records<T, F>(values: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    let mut object = serde_json::Map::new();
    for (key, value) in values {
        object.insert(key.clone(), public_record(value));
    }
    Value::Object(object)
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value)
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-AA-PAYMASTER-VOUCHER-{domain}"),
        &leaves,
    )
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| {
            json!({
                "value": value
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-AA-PAYMASTER-VOUCHER-{domain}"),
        &leaves,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-AA-PAYMASTER-VOUCHER-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
