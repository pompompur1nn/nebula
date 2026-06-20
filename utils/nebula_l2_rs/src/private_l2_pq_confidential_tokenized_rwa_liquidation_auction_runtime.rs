use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedRwaLiquidationAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_LIQUIDATION_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-rwa-liquidation-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_LIQUIDATION_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_RWA_REGISTRY: &str = "nebula-tokenized-rwa-registry-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "rwa-note-pool-devnet";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "dusd-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const COLLATERAL_LOT_SCHEME: &str = "confidential-tokenized-rwa-collateral-lot-root-v1";
pub const SEALED_BID_SCHEME: &str = "ml-kem-1024-sealed-rwa-liquidation-bid-root-v1";
pub const PRIVATE_BIDDER_COMMITMENT_SCHEME: &str = "private-bidder-rwa-commitment-root-v1";
pub const ORACLE_HAIRCUT_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-rwa-haircut-attestation-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str = "low-fee-confidential-rwa-liquidation-batch-root-v1";
pub const FEE_REBATE_SCHEME: &str = "confidential-rwa-liquidation-fee-rebate-root-v1";
pub const COMPLIANCE_REDACTION_SCHEME: &str = "view-key-safe-rwa-liquidation-redaction-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-rwa-liquidation-summary-root-v1";
pub const NULLIFIER_SCHEME: &str = "private-rwa-liquidation-nullifier-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_bid_amounts_borrower_ids_or_bidder_ids";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_LOW_FEE_BATCH_BPS: u64 = 5;
pub const DEFAULT_MAX_LIQUIDATION_DISCOUNT_BPS: u64 = 3_500;
pub const DEFAULT_TARGET_HAIRCUT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_HAIRCUT_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MIN_BID_COVERAGE_BPS: u64 = 8_500;
pub const DEFAULT_TARGET_BID_COVERAGE_BPS: u64 = 10_250;
pub const DEFAULT_MAX_BATCH_LOTS: usize = 512;
pub const DEFAULT_MAX_BATCH_BIDS: usize = 2_048;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_OPERATOR_BUCKET_SIZE: u64 = 64;
pub const MAX_COLLATERAL_LOTS: usize = 524_288;
pub const MAX_SEALED_BIDS: usize = 2_097_152;
pub const MAX_BIDDER_COMMITMENTS: usize = 1_048_576;
pub const MAX_HAIRCUT_ATTESTATIONS: usize = 1_048_576;
pub const MAX_SETTLEMENT_BATCHES: usize = 262_144;
pub const MAX_FEE_REBATES: usize = 524_288;
pub const MAX_COMPLIANCE_REDACTIONS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaClass {
    TreasuryBill,
    PrivateCredit,
    RealEstateNote,
    InvoiceReceivable,
    CarbonCredit,
    CommodityReceipt,
    FundShare,
    InsuranceClaim,
}
impl RwaClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TreasuryBill => "treasury_bill",
            Self::PrivateCredit => "private_credit",
            Self::RealEstateNote => "real_estate_note",
            Self::InvoiceReceivable => "invoice_receivable",
            Self::CarbonCredit => "carbon_credit",
            Self::CommodityReceipt => "commodity_receipt",
            Self::FundShare => "fund_share",
            Self::InsuranceClaim => "insurance_claim",
        }
    }
    pub fn baseline_haircut_bps(self) -> u64 {
        match self {
            Self::TreasuryBill => 250,
            Self::PrivateCredit => 1800,
            Self::RealEstateNote => 1250,
            Self::InvoiceReceivable => 1500,
            Self::CarbonCredit => 2750,
            Self::CommodityReceipt => 1100,
            Self::FundShare => 900,
            Self::InsuranceClaim => 2250,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralLotStatus {
    Draft,
    MarginCalled,
    IntakeSealed,
    OracleAttested,
    AuctionOpen,
    Clearing,
    Settled,
    Released,
    Rejected,
    Expired,
}
impl CollateralLotStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::OracleAttested | Self::AuctionOpen)
    }
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Released | Self::Rejected | Self::Expired
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    EligibilityChecked,
    HaircutMatched,
    Selected,
    Batched,
    Settled,
    Refunded,
    Rejected,
    Expired,
}
impl BidStatus {
    pub fn eligible_for_clearing(self) -> bool {
        matches!(
            self,
            Self::EligibilityChecked | Self::HaircutMatched | Self::Selected
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Superseded,
    Revoked,
    Rejected,
    Expired,
}
impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Locked,
    Clearing,
    Netting,
    Posted,
    Finalized,
    Disputed,
    Rejected,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Requested,
    Approved,
    Applied,
    Exhausted,
    Revoked,
    Rejected,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAudience {
    Operator,
    Liquidator,
    Oracle,
    Compliance,
    Sponsor,
    Public,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    LotRegistered,
    LotHaircutAttested,
    BidCommitted,
    BidSelected,
    BatchOpened,
    BatchCleared,
    RebateIssued,
    RedactionApplied,
    SummaryPublished,
    NullifierObserved,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub rwa_registry: String,
    pub collateral_asset_id: String,
    pub settlement_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub collateral_lot_scheme: String,
    pub sealed_bid_scheme: String,
    pub bidder_commitment_scheme: String,
    pub oracle_haircut_attestation_scheme: String,
    pub settlement_batch_scheme: String,
    pub fee_rebate_scheme: String,
    pub compliance_redaction_scheme: String,
    pub operator_summary_scheme: String,
    pub nullifier_scheme: String,
    pub privacy_boundary: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_batch_bps: u64,
    pub max_liquidation_discount_bps: u64,
    pub target_haircut_quorum_bps: u64,
    pub strong_haircut_quorum_bps: u64,
    pub min_bid_coverage_bps: u64,
    pub target_bid_coverage_bps: u64,
    pub max_batch_lots: usize,
    pub max_batch_bids: usize,
    pub auction_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub operator_bucket_size: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            rwa_registry: DEVNET_RWA_REGISTRY.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            collateral_lot_scheme: COLLATERAL_LOT_SCHEME.to_string(),
            sealed_bid_scheme: SEALED_BID_SCHEME.to_string(),
            bidder_commitment_scheme: PRIVATE_BIDDER_COMMITMENT_SCHEME.to_string(),
            oracle_haircut_attestation_scheme: ORACLE_HAIRCUT_ATTESTATION_SCHEME.to_string(),
            settlement_batch_scheme: SETTLEMENT_BATCH_SCHEME.to_string(),
            fee_rebate_scheme: FEE_REBATE_SCHEME.to_string(),
            compliance_redaction_scheme: COMPLIANCE_REDACTION_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            nullifier_scheme: NULLIFIER_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_batch_bps: DEFAULT_LOW_FEE_BATCH_BPS,
            max_liquidation_discount_bps: DEFAULT_MAX_LIQUIDATION_DISCOUNT_BPS,
            target_haircut_quorum_bps: DEFAULT_TARGET_HAIRCUT_QUORUM_BPS,
            strong_haircut_quorum_bps: DEFAULT_STRONG_HAIRCUT_QUORUM_BPS,
            min_bid_coverage_bps: DEFAULT_MIN_BID_COVERAGE_BPS,
            target_bid_coverage_bps: DEFAULT_TARGET_BID_COVERAGE_BPS,
            max_batch_lots: DEFAULT_MAX_BATCH_LOTS,
            max_batch_bids: DEFAULT_MAX_BATCH_BIDS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            operator_bucket_size: DEFAULT_OPERATOR_BUCKET_SIZE,
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub collateral_lots: u64,
    pub sealed_bids: u64,
    pub bidder_commitments: u64,
    pub haircut_attestations: u64,
    pub settlement_batches: u64,
    pub fee_rebates: u64,
    pub compliance_redactions: u64,
    pub operator_summaries: u64,
    pub nullifiers: u64,
    pub selected_bids: u64,
    pub settled_lots: u64,
    pub rejected_records: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub collateral_lot_root: String,
    pub sealed_bid_root: String,
    pub bidder_commitment_root: String,
    pub haircut_attestation_root: String,
    pub settlement_batch_root: String,
    pub fee_rebate_root: String,
    pub compliance_redaction_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub liquidity_root: String,
    pub clearance_root: String,
    pub state_root: String,
}
impl Default for Roots {
    fn default() -> Self {
        Self {
            collateral_lot_root: empty_root("PRIVATE-L2-RWA-COLLATERAL-LOT"),
            sealed_bid_root: empty_root("PRIVATE-L2-RWA-SEALED-BID"),
            bidder_commitment_root: empty_root("PRIVATE-L2-RWA-BIDDER-COMMITMENT"),
            haircut_attestation_root: empty_root("PRIVATE-L2-RWA-HAIRCUT-ATTESTATION"),
            settlement_batch_root: empty_root("PRIVATE-L2-RWA-SETTLEMENT-BATCH"),
            fee_rebate_root: empty_root("PRIVATE-L2-RWA-FEE-REBATE"),
            compliance_redaction_root: empty_root("PRIVATE-L2-RWA-COMPLIANCE-REDACTION"),
            operator_summary_root: empty_root("PRIVATE-L2-RWA-OPERATOR-SUMMARY"),
            nullifier_root: empty_root("PRIVATE-L2-RWA-NULLIFIER"),
            event_root: empty_root("PRIVATE-L2-RWA-EVENT"),
            liquidity_root: tagged_root("empty-liquidity-root"),
            clearance_root: tagged_root("empty-clearance-root"),
            state_root: tagged_root("empty-state-root"),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationEnvelope {
    pub scheme: String,
    pub signer_commitment: String,
    pub public_key_commitment: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub aggregate_signature_root: String,
    pub security_bits: u16,
}
impl PqAttestationEnvelope {
    pub fn public_record(&self) -> Value {
        json!({"scheme":self.scheme,"signer_commitment":self.signer_commitment,"public_key_commitment":self.public_key_commitment,"transcript_hash":self.transcript_hash,"signature_commitment":self.signature_commitment,"aggregate_signature_root":self.aggregate_signature_root,"security_bits":self.security_bits})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RwaCollateralLot {
    pub lot_id: String,
    pub vault_id: String,
    pub borrower_commitment: String,
    pub rwa_class: RwaClass,
    pub collateral_token_commitment: String,
    pub collateral_registry_root: String,
    pub jurisdiction_commitment: String,
    pub lien_commitment_root: String,
    pub valuation_commitment: String,
    pub debt_commitment: String,
    pub reserve_price_commitment: String,
    pub haircut_bps: u64,
    pub liquidation_discount_bps: u64,
    pub min_bid_coverage_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: CollateralLotStatus,
    pub bid_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub selected_bid_id: Option<String>,
    pub settlement_batch_id: Option<String>,
    pub lot_nullifier: String,
}
impl RwaCollateralLot {
    pub fn public_record(&self) -> Value {
        json!({"lot_id":self.lot_id,"vault_id":self.vault_id,"borrower_commitment":self.borrower_commitment,"rwa_class":self.rwa_class,"collateral_token_commitment":self.collateral_token_commitment,"collateral_registry_root":self.collateral_registry_root,"jurisdiction_commitment":self.jurisdiction_commitment,"lien_commitment_root":self.lien_commitment_root,"valuation_commitment":self.valuation_commitment,"debt_commitment":self.debt_commitment,"reserve_price_commitment":self.reserve_price_commitment,"haircut_bps":self.haircut_bps,"liquidation_discount_bps":self.liquidation_discount_bps,"min_bid_coverage_bps":self.min_bid_coverage_bps,"privacy_set_size":self.privacy_set_size,"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height,"status":self.status,"bid_ids":self.bid_ids,"attestation_ids":self.attestation_ids,"selected_bid_id":self.selected_bid_id,"settlement_batch_id":self.settlement_batch_id,"lot_nullifier":self.lot_nullifier})
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height && !self.status.is_terminal()
    }
    pub fn effective_haircut_bps(&self) -> u64 {
        self.haircut_bps
            .saturating_add(self.rwa_class.baseline_haircut_bps())
            .min(MAX_BPS)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateBidderCommitment {
    pub bidder_commitment_id: String,
    pub bidder_group_root: String,
    pub kyc_attestation_root: String,
    pub accreditation_commitment: String,
    pub sanctions_screen_root: String,
    pub funding_commitment_root: String,
    pub settlement_address_commitment: String,
    pub encrypted_contact_route: String,
    pub pq_envelope: PqAttestationEnvelope,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}
impl PrivateBidderCommitment {
    pub fn public_record(&self) -> Value {
        json!({"bidder_commitment_id":self.bidder_commitment_id,"bidder_group_root":self.bidder_group_root,"kyc_attestation_root":self.kyc_attestation_root,"accreditation_commitment":self.accreditation_commitment,"sanctions_screen_root":self.sanctions_screen_root,"funding_commitment_root":self.funding_commitment_root,"settlement_address_commitment":self.settlement_address_commitment,"encrypted_contact_route":self.encrypted_contact_route,"pq_envelope":self.pq_envelope.public_record(),"privacy_set_size":self.privacy_set_size,"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height,"active":self.active})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedLiquidationBid {
    pub bid_id: String,
    pub lot_id: String,
    pub bidder_commitment_id: String,
    pub bid_ciphertext_hash: String,
    pub price_commitment: String,
    pub max_haircut_bps: u64,
    pub fee_limit_bps: u64,
    pub settlement_asset_commitment: String,
    pub funding_proof_root: String,
    pub bidder_rebate_commitment: String,
    pub compliance_tag_root: String,
    pub bid_nullifier: String,
    pub pq_envelope: PqAttestationEnvelope,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: BidStatus,
}
impl SealedLiquidationBid {
    pub fn public_record(&self) -> Value {
        json!({"bid_id":self.bid_id,"lot_id":self.lot_id,"bidder_commitment_id":self.bidder_commitment_id,"bid_ciphertext_hash":self.bid_ciphertext_hash,"price_commitment":self.price_commitment,"max_haircut_bps":self.max_haircut_bps,"fee_limit_bps":self.fee_limit_bps,"settlement_asset_commitment":self.settlement_asset_commitment,"funding_proof_root":self.funding_proof_root,"bidder_rebate_commitment":self.bidder_rebate_commitment,"compliance_tag_root":self.compliance_tag_root,"bid_nullifier":self.bid_nullifier,"pq_envelope":self.pq_envelope.public_record(),"submitted_at_height":self.submitted_at_height,"expires_at_height":self.expires_at_height,"status":self.status})
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
            && !matches!(
                self.status,
                BidStatus::Settled | BidStatus::Refunded | BidStatus::Rejected
            )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleHaircutAttestation {
    pub attestation_id: String,
    pub lot_id: String,
    pub oracle_set_root: String,
    pub price_source_root: String,
    pub valuation_commitment: String,
    pub haircut_bps: u64,
    pub confidence_bps: u64,
    pub quorum_bps: u64,
    pub market_stress_bps: u64,
    pub stale_after_height: u64,
    pub signed_at_height: u64,
    pub status: AttestationStatus,
    pub pq_envelope: PqAttestationEnvelope,
}
impl OracleHaircutAttestation {
    pub fn public_record(&self) -> Value {
        json!({"attestation_id":self.attestation_id,"lot_id":self.lot_id,"oracle_set_root":self.oracle_set_root,"price_source_root":self.price_source_root,"valuation_commitment":self.valuation_commitment,"haircut_bps":self.haircut_bps,"confidence_bps":self.confidence_bps,"quorum_bps":self.quorum_bps,"market_stress_bps":self.market_stress_bps,"stale_after_height":self.stale_after_height,"signed_at_height":self.signed_at_height,"status":self.status,"pq_envelope":self.pq_envelope.public_record()})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub lot_ids: BTreeSet<String>,
    pub selected_bid_ids: BTreeSet<String>,
    pub settlement_asset_commitment: String,
    pub clearing_price_root: String,
    pub transfer_manifest_root: String,
    pub compliance_manifest_root: String,
    pub fee_commitment: String,
    pub fee_bps: u64,
    pub rebate_pool_commitment: String,
    pub low_fee_sponsor_commitment: String,
    pub netting_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub status: SettlementStatus,
}
impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({"batch_id":self.batch_id,"lot_ids":self.lot_ids,"selected_bid_ids":self.selected_bid_ids,"settlement_asset_commitment":self.settlement_asset_commitment,"clearing_price_root":self.clearing_price_root,"transfer_manifest_root":self.transfer_manifest_root,"compliance_manifest_root":self.compliance_manifest_root,"fee_commitment":self.fee_commitment,"fee_bps":self.fee_bps,"rebate_pool_commitment":self.rebate_pool_commitment,"low_fee_sponsor_commitment":self.low_fee_sponsor_commitment,"netting_root":self.netting_root,"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height,"finalized_at_height":self.finalized_at_height,"status":self.status})
    }
    pub fn is_low_fee(&self, config: &Config) -> bool {
        self.fee_bps <= config.low_fee_batch_bps
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub bid_id: String,
    pub bidder_commitment_id: String,
    pub rebate_commitment: String,
    pub sponsor_commitment: String,
    pub fee_paid_commitment: String,
    pub eligibility_root: String,
    pub issued_at_height: u64,
    pub claimed: bool,
}
impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({"rebate_id":self.rebate_id,"batch_id":self.batch_id,"bid_id":self.bid_id,"bidder_commitment_id":self.bidder_commitment_id,"rebate_commitment":self.rebate_commitment,"sponsor_commitment":self.sponsor_commitment,"fee_paid_commitment":self.fee_paid_commitment,"eligibility_root":self.eligibility_root,"issued_at_height":self.issued_at_height,"claimed":self.claimed})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceRedaction {
    pub redaction_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub redacted_fields_root: String,
    pub disclosure_audience: SummaryAudience,
    pub regulator_commitment: String,
    pub warrant_commitment: String,
    pub view_key_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: RedactionStatus,
}
impl ComplianceRedaction {
    pub fn public_record(&self) -> Value {
        json!({"redaction_id":self.redaction_id,"subject_kind":self.subject_kind,"subject_id":self.subject_id,"redacted_fields_root":self.redacted_fields_root,"disclosure_audience":self.disclosure_audience,"regulator_commitment":self.regulator_commitment,"warrant_commitment":self.warrant_commitment,"view_key_policy_root":self.view_key_policy_root,"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height,"status":self.status})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub audience: SummaryAudience,
    pub epoch: u64,
    pub lot_count: u64,
    pub bid_count: u64,
    pub selected_bid_count: u64,
    pub settled_lot_count: u64,
    pub low_fee_batch_count: u64,
    pub average_fee_bps: u64,
    pub haircut_commitment_root: String,
    pub liquidity_commitment_root: String,
    pub compliance_redaction_root: String,
    pub published_at_height: u64,
}
impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({"summary_id":self.summary_id,"audience":self.audience,"epoch":self.epoch,"lot_count":self.lot_count,"bid_count":self.bid_count,"selected_bid_count":self.selected_bid_count,"settled_lot_count":self.settled_lot_count,"low_fee_batch_count":self.low_fee_batch_count,"average_fee_bps":self.average_fee_bps,"haircut_commitment_root":self.haircut_commitment_root,"liquidity_commitment_root":self.liquidity_commitment_root,"compliance_redaction_root":self.compliance_redaction_root,"published_at_height":self.published_at_height})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: RuntimeEventKind,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({"event_id":self.event_id,"kind":self.kind,"subject_id":self.subject_id,"payload_root":self.payload_root,"height":self.height})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub collateral_lots: BTreeMap<String, RwaCollateralLot>,
    pub sealed_bids: BTreeMap<String, SealedLiquidationBid>,
    pub bidder_commitments: BTreeMap<String, PrivateBidderCommitment>,
    pub haircut_attestations: BTreeMap<String, OracleHaircutAttestation>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub compliance_redactions: BTreeMap<String, ComplianceRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}
impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), 0)
    }
}
impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height,
            collateral_lots: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            bidder_commitments: BTreeMap::new(),
            haircut_attestations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            compliance_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default(), 812_000);
        seed_devnet(&mut state);
        state
    }
    pub fn public_record(&self) -> Value {
        json!({"protocol_version":self.config.protocol_version,"schema_version":self.config.schema_version,"chain_id":self.config.chain_id,"l2_network":self.config.l2_network,"rwa_registry":self.config.rwa_registry,"collateral_asset_id":self.config.collateral_asset_id,"settlement_asset_id":self.config.settlement_asset_id,"fee_asset_id":self.config.fee_asset_id,"privacy_boundary":self.config.privacy_boundary,"current_height":self.current_height,"counters":self.counters,"roots":self.roots,"collateral_lots":self.collateral_lots.values().map(RwaCollateralLot::public_record).collect::<Vec<_>>(),"sealed_bids":self.sealed_bids.values().map(SealedLiquidationBid::public_record).collect::<Vec<_>>(),"bidder_commitments":self.bidder_commitments.values().map(PrivateBidderCommitment::public_record).collect::<Vec<_>>(),"haircut_attestations":self.haircut_attestations.values().map(OracleHaircutAttestation::public_record).collect::<Vec<_>>(),"settlement_batches":self.settlement_batches.values().map(SettlementBatch::public_record).collect::<Vec<_>>(),"fee_rebates":self.fee_rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),"compliance_redactions":self.compliance_redactions.values().map(ComplianceRedaction::public_record).collect::<Vec<_>>(),"operator_summaries":self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>()})
    }
    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.current_height {
            return Err("height cannot move backwards".to_string());
        }
        self.current_height = height;
        self.expire_stale_records();
        self.recompute_roots();
        Ok(())
    }
    pub fn register_bidder_commitment(
        &mut self,
        bidder_group_root: impl Into<String>,
        kyc_attestation_root: impl Into<String>,
        accreditation_commitment: impl Into<String>,
        sanctions_screen_root: impl Into<String>,
        funding_commitment_root: impl Into<String>,
        settlement_address_commitment: impl Into<String>,
        encrypted_contact_route: impl Into<String>,
        privacy_set_size: u64,
        pq_envelope: PqAttestationEnvelope,
    ) -> Result<String> {
        ensure_capacity(
            self.bidder_commitments.len(),
            MAX_BIDDER_COMMITMENTS,
            "bidder commitments",
        )?;
        ensure_privacy_set(privacy_set_size, &self.config)?;
        ensure_pq_security(&pq_envelope, &self.config)?;
        let bidder_group_root = bidder_group_root.into();
        let kyc_attestation_root = kyc_attestation_root.into();
        let funding_commitment_root = funding_commitment_root.into();
        let id = bidder_commitment_id(
            &bidder_group_root,
            &kyc_attestation_root,
            &funding_commitment_root,
            self.current_height,
            self.counters.next_sequence,
        );
        let commitment = PrivateBidderCommitment {
            bidder_commitment_id: id.clone(),
            bidder_group_root,
            kyc_attestation_root,
            accreditation_commitment: accreditation_commitment.into(),
            sanctions_screen_root: sanctions_screen_root.into(),
            funding_commitment_root,
            settlement_address_commitment: settlement_address_commitment.into(),
            encrypted_contact_route: encrypted_contact_route.into(),
            pq_envelope,
            privacy_set_size,
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.auction_ttl_blocks * 4),
            active: true,
        };
        self.bidder_commitments.insert(id.clone(), commitment);
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.counters.bidder_commitments = self.counters.bidder_commitments.saturating_add(1);
        self.push_event(
            RuntimeEventKind::BidCommitted,
            &id,
            json!({"record":"bidder_commitment"}),
        );
        self.recompute_roots();
        Ok(id)
    }
    pub fn open_collateral_lot(
        &mut self,
        vault_id: impl Into<String>,
        borrower_commitment: impl Into<String>,
        rwa_class: RwaClass,
        collateral_token_commitment: impl Into<String>,
        collateral_registry_root: impl Into<String>,
        jurisdiction_commitment: impl Into<String>,
        lien_commitment_root: impl Into<String>,
        valuation_commitment: impl Into<String>,
        debt_commitment: impl Into<String>,
        reserve_price_commitment: impl Into<String>,
        liquidation_discount_bps: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.collateral_lots.len(),
            MAX_COLLATERAL_LOTS,
            "collateral lots",
        )?;
        ensure_privacy_set(privacy_set_size, &self.config)?;
        if liquidation_discount_bps > self.config.max_liquidation_discount_bps {
            return Err("liquidation discount exceeds configured maximum".to_string());
        }
        let vault_id = vault_id.into();
        let borrower_commitment = borrower_commitment.into();
        let collateral_token_commitment = collateral_token_commitment.into();
        let lot_nullifier = collateral_lot_nullifier(
            &vault_id,
            &borrower_commitment,
            &collateral_token_commitment,
        );
        ensure_new_nullifier(&self.nullifiers, &lot_nullifier)?;
        let lot_id = collateral_lot_id(
            &vault_id,
            &borrower_commitment,
            &collateral_token_commitment,
            self.current_height,
            self.counters.next_sequence,
        );
        let lot = RwaCollateralLot {
            lot_id: lot_id.clone(),
            vault_id,
            borrower_commitment,
            rwa_class,
            collateral_token_commitment,
            collateral_registry_root: collateral_registry_root.into(),
            jurisdiction_commitment: jurisdiction_commitment.into(),
            lien_commitment_root: lien_commitment_root.into(),
            valuation_commitment: valuation_commitment.into(),
            debt_commitment: debt_commitment.into(),
            reserve_price_commitment: reserve_price_commitment.into(),
            haircut_bps: rwa_class.baseline_haircut_bps(),
            liquidation_discount_bps,
            min_bid_coverage_bps: self.config.min_bid_coverage_bps,
            privacy_set_size,
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.auction_ttl_blocks),
            status: CollateralLotStatus::MarginCalled,
            bid_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            selected_bid_id: None,
            settlement_batch_id: None,
            lot_nullifier: lot_nullifier.clone(),
        };
        self.nullifiers.insert(lot_nullifier);
        self.collateral_lots.insert(lot_id.clone(), lot);
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.counters.collateral_lots = self.counters.collateral_lots.saturating_add(1);
        self.counters.nullifiers = self.counters.nullifiers.saturating_add(1);
        self.push_event(
            RuntimeEventKind::LotRegistered,
            &lot_id,
            json!({"rwa_class":rwa_class}),
        );
        self.recompute_roots();
        Ok(lot_id)
    }
    pub fn attest_haircut(
        &mut self,
        lot_id: &str,
        oracle_set_root: impl Into<String>,
        price_source_root: impl Into<String>,
        valuation_commitment: impl Into<String>,
        haircut_bps: u64,
        confidence_bps: u64,
        quorum_bps: u64,
        market_stress_bps: u64,
        pq_envelope: PqAttestationEnvelope,
    ) -> Result<String> {
        ensure_capacity(
            self.haircut_attestations.len(),
            MAX_HAIRCUT_ATTESTATIONS,
            "haircut attestations",
        )?;
        ensure_pq_security(&pq_envelope, &self.config)?;
        ensure_bps(haircut_bps, "haircut")?;
        ensure_bps(confidence_bps, "confidence")?;
        ensure_bps(quorum_bps, "quorum")?;
        ensure_bps(market_stress_bps, "market stress")?;
        let lot = self
            .collateral_lots
            .get_mut(lot_id)
            .ok_or_else(|| "unknown collateral lot".to_string())?;
        if lot.status.is_terminal() {
            return Err("cannot attest terminal lot".to_string());
        }
        let oracle_set_root = oracle_set_root.into();
        let price_source_root = price_source_root.into();
        let id = haircut_attestation_id(
            lot_id,
            &oracle_set_root,
            &price_source_root,
            haircut_bps,
            self.current_height,
        );
        let status = if quorum_bps >= self.config.strong_haircut_quorum_bps {
            AttestationStatus::StrongQuorum
        } else if quorum_bps >= self.config.target_haircut_quorum_bps {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
        let attestation = OracleHaircutAttestation {
            attestation_id: id.clone(),
            lot_id: lot_id.to_string(),
            oracle_set_root,
            price_source_root,
            valuation_commitment: valuation_commitment.into(),
            haircut_bps,
            confidence_bps,
            quorum_bps,
            market_stress_bps,
            stale_after_height: self
                .current_height
                .saturating_add(self.config.attestation_ttl_blocks),
            signed_at_height: self.current_height,
            status,
            pq_envelope,
        };
        lot.haircut_bps = lot
            .haircut_bps
            .max(haircut_bps.saturating_add(market_stress_bps).min(MAX_BPS));
        lot.attestation_ids.insert(id.clone());
        lot.status = CollateralLotStatus::OracleAttested;
        self.haircut_attestations.insert(id.clone(), attestation);
        self.counters.haircut_attestations = self.counters.haircut_attestations.saturating_add(1);
        self.push_event(
            RuntimeEventKind::LotHaircutAttested,
            lot_id,
            json!({"attestation_id":id}),
        );
        self.recompute_roots();
        Ok(id)
    }
    pub fn submit_sealed_bid(
        &mut self,
        lot_id: &str,
        bidder_commitment_id: &str,
        bid_ciphertext_hash: impl Into<String>,
        price_commitment: impl Into<String>,
        max_haircut_bps: u64,
        fee_limit_bps: u64,
        settlement_asset_commitment: impl Into<String>,
        funding_proof_root: impl Into<String>,
        bidder_rebate_commitment: impl Into<String>,
        compliance_tag_root: impl Into<String>,
        pq_envelope: PqAttestationEnvelope,
    ) -> Result<String> {
        ensure_capacity(self.sealed_bids.len(), MAX_SEALED_BIDS, "sealed bids")?;
        ensure_bps(max_haircut_bps, "max haircut")?;
        ensure_fee(fee_limit_bps, self.config.max_user_fee_bps)?;
        ensure_pq_security(&pq_envelope, &self.config)?;
        let bidder = self
            .bidder_commitments
            .get(bidder_commitment_id)
            .ok_or_else(|| "unknown bidder commitment".to_string())?;
        if !bidder.active || bidder.expires_at_height < self.current_height {
            return Err("bidder commitment inactive or expired".to_string());
        }
        let lot = self
            .collateral_lots
            .get_mut(lot_id)
            .ok_or_else(|| "unknown collateral lot".to_string())?;
        if !lot.status.accepts_bids() {
            return Err("lot is not accepting sealed bids".to_string());
        }
        if max_haircut_bps < lot.effective_haircut_bps() {
            return Err("sealed bid haircut tolerance below lot haircut".to_string());
        }
        let bid_ciphertext_hash = bid_ciphertext_hash.into();
        let bid_nullifier = bid_nullifier(lot_id, bidder_commitment_id, &bid_ciphertext_hash);
        ensure_new_nullifier(&self.nullifiers, &bid_nullifier)?;
        let bid_id = sealed_bid_id(
            lot_id,
            bidder_commitment_id,
            &bid_ciphertext_hash,
            self.current_height,
            self.counters.next_sequence,
        );
        let bid = SealedLiquidationBid {
            bid_id: bid_id.clone(),
            lot_id: lot_id.to_string(),
            bidder_commitment_id: bidder_commitment_id.to_string(),
            bid_ciphertext_hash,
            price_commitment: price_commitment.into(),
            max_haircut_bps,
            fee_limit_bps,
            settlement_asset_commitment: settlement_asset_commitment.into(),
            funding_proof_root: funding_proof_root.into(),
            bidder_rebate_commitment: bidder_rebate_commitment.into(),
            compliance_tag_root: compliance_tag_root.into(),
            bid_nullifier: bid_nullifier.clone(),
            pq_envelope,
            submitted_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.bid_ttl_blocks),
            status: BidStatus::EligibilityChecked,
        };
        lot.bid_ids.insert(bid_id.clone());
        lot.status = CollateralLotStatus::AuctionOpen;
        self.nullifiers.insert(bid_nullifier);
        self.sealed_bids.insert(bid_id.clone(), bid);
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.counters.sealed_bids = self.counters.sealed_bids.saturating_add(1);
        self.counters.nullifiers = self.counters.nullifiers.saturating_add(1);
        self.push_event(
            RuntimeEventKind::BidCommitted,
            &bid_id,
            json!({"lot_id":lot_id}),
        );
        self.recompute_roots();
        Ok(bid_id)
    }
    pub fn select_bid(&mut self, lot_id: &str, bid_id: &str) -> Result<()> {
        let lot = self
            .collateral_lots
            .get_mut(lot_id)
            .ok_or_else(|| "unknown collateral lot".to_string())?;
        if !lot.bid_ids.contains(bid_id) {
            return Err("bid is not attached to lot".to_string());
        }
        let bid = self
            .sealed_bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown sealed bid".to_string())?;
        if !bid.status.eligible_for_clearing() {
            return Err("bid is not eligible for clearing".to_string());
        }
        if bid.expires_at_height < self.current_height {
            bid.status = BidStatus::Expired;
            return Err("bid expired".to_string());
        }
        bid.status = BidStatus::Selected;
        lot.selected_bid_id = Some(bid_id.to_string());
        lot.status = CollateralLotStatus::Clearing;
        self.counters.selected_bids = self.counters.selected_bids.saturating_add(1);
        self.push_event(
            RuntimeEventKind::BidSelected,
            bid_id,
            json!({"lot_id":lot_id}),
        );
        self.recompute_roots();
        Ok(())
    }
    pub fn open_settlement_batch(
        &mut self,
        lot_ids: BTreeSet<String>,
        settlement_asset_commitment: impl Into<String>,
        clearing_price_root: impl Into<String>,
        transfer_manifest_root: impl Into<String>,
        compliance_manifest_root: impl Into<String>,
        fee_commitment: impl Into<String>,
        fee_bps: u64,
        rebate_pool_commitment: impl Into<String>,
        low_fee_sponsor_commitment: impl Into<String>,
        netting_root: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity(
            self.settlement_batches.len(),
            MAX_SETTLEMENT_BATCHES,
            "settlement batches",
        )?;
        if lot_ids.is_empty() || lot_ids.len() > self.config.max_batch_lots {
            return Err("invalid lot count for settlement batch".to_string());
        }
        ensure_fee(fee_bps, self.config.max_user_fee_bps)?;
        let mut selected_bid_ids = BTreeSet::new();
        for lot_id in &lot_ids {
            let lot = self
                .collateral_lots
                .get(lot_id)
                .ok_or_else(|| format!("unknown lot {lot_id}"))?;
            selected_bid_ids.insert(
                lot.selected_bid_id
                    .clone()
                    .ok_or_else(|| format!("lot {lot_id} has no selected bid"))?,
            );
        }
        if selected_bid_ids.len() > self.config.max_batch_bids {
            return Err("too many selected bids for settlement batch".to_string());
        }
        let clearing_price_root = clearing_price_root.into();
        let batch_id = settlement_batch_id(
            &lot_ids,
            &selected_bid_ids,
            &clearing_price_root,
            self.current_height,
            self.counters.next_sequence,
        );
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            lot_ids: lot_ids.clone(),
            selected_bid_ids: selected_bid_ids.clone(),
            settlement_asset_commitment: settlement_asset_commitment.into(),
            clearing_price_root,
            transfer_manifest_root: transfer_manifest_root.into(),
            compliance_manifest_root: compliance_manifest_root.into(),
            fee_commitment: fee_commitment.into(),
            fee_bps,
            rebate_pool_commitment: rebate_pool_commitment.into(),
            low_fee_sponsor_commitment: low_fee_sponsor_commitment.into(),
            netting_root: netting_root.into(),
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.settlement_ttl_blocks),
            finalized_at_height: None,
            status: SettlementStatus::Locked,
        };
        for lot_id in &lot_ids {
            if let Some(lot) = self.collateral_lots.get_mut(lot_id) {
                lot.settlement_batch_id = Some(batch_id.clone());
                lot.status = CollateralLotStatus::Clearing;
            }
        }
        for bid_id in &selected_bid_ids {
            if let Some(bid) = self.sealed_bids.get_mut(bid_id) {
                bid.status = BidStatus::Batched;
            }
        }
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.counters.settlement_batches = self.counters.settlement_batches.saturating_add(1);
        self.push_event(
            RuntimeEventKind::BatchOpened,
            &batch_id,
            json!({"lot_count":lot_ids.len()}),
        );
        self.recompute_roots();
        Ok(batch_id)
    }
    pub fn finalize_settlement_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        if batch.expires_at_height < self.current_height {
            batch.status = SettlementStatus::Disputed;
            return Err("settlement batch expired".to_string());
        }
        batch.status = SettlementStatus::Finalized;
        batch.finalized_at_height = Some(self.current_height);
        let lot_ids = batch.lot_ids.clone();
        let bid_ids = batch.selected_bid_ids.clone();
        for lot_id in lot_ids {
            if let Some(lot) = self.collateral_lots.get_mut(&lot_id) {
                lot.status = CollateralLotStatus::Settled;
                self.counters.settled_lots = self.counters.settled_lots.saturating_add(1);
            }
        }
        for bid_id in bid_ids {
            if let Some(bid) = self.sealed_bids.get_mut(&bid_id) {
                bid.status = BidStatus::Settled;
            }
        }
        self.push_event(
            RuntimeEventKind::BatchCleared,
            batch_id,
            json!({"status":"finalized"}),
        );
        self.recompute_roots();
        Ok(())
    }
    pub fn issue_fee_rebate(
        &mut self,
        batch_id: &str,
        bid_id: &str,
        rebate_commitment: impl Into<String>,
        sponsor_commitment: impl Into<String>,
        fee_paid_commitment: impl Into<String>,
        eligibility_root: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity(self.fee_rebates.len(), MAX_FEE_REBATES, "fee rebates")?;
        let batch = self
            .settlement_batches
            .get(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        if !batch.selected_bid_ids.contains(bid_id) {
            return Err("bid not included in batch".to_string());
        }
        if !batch.is_low_fee(&self.config) {
            return Err("rebates are reserved for low-fee batches".to_string());
        }
        let bid = self
            .sealed_bids
            .get(bid_id)
            .ok_or_else(|| "unknown sealed bid".to_string())?;
        let rebate_id = fee_rebate_id(
            batch_id,
            bid_id,
            &bid.bidder_commitment_id,
            self.current_height,
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            batch_id: batch_id.to_string(),
            bid_id: bid_id.to_string(),
            bidder_commitment_id: bid.bidder_commitment_id.clone(),
            rebate_commitment: rebate_commitment.into(),
            sponsor_commitment: sponsor_commitment.into(),
            fee_paid_commitment: fee_paid_commitment.into(),
            eligibility_root: eligibility_root.into(),
            issued_at_height: self.current_height,
            claimed: false,
        };
        self.fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.fee_rebates = self.counters.fee_rebates.saturating_add(1);
        self.push_event(
            RuntimeEventKind::RebateIssued,
            &rebate_id,
            json!({"batch_id":batch_id}),
        );
        self.recompute_roots();
        Ok(rebate_id)
    }
    pub fn apply_compliance_redaction(
        &mut self,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        redacted_fields_root: impl Into<String>,
        disclosure_audience: SummaryAudience,
        regulator_commitment: impl Into<String>,
        warrant_commitment: impl Into<String>,
        view_key_policy_root: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity(
            self.compliance_redactions.len(),
            MAX_COMPLIANCE_REDACTIONS,
            "compliance redactions",
        )?;
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let redacted_fields_root = redacted_fields_root.into();
        let redaction_id = compliance_redaction_id(
            &subject_kind,
            &subject_id,
            &redacted_fields_root,
            self.current_height,
        );
        let redaction = ComplianceRedaction {
            redaction_id: redaction_id.clone(),
            subject_kind,
            subject_id: subject_id.clone(),
            redacted_fields_root,
            disclosure_audience,
            regulator_commitment: regulator_commitment.into(),
            warrant_commitment: warrant_commitment.into(),
            view_key_policy_root: view_key_policy_root.into(),
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.redaction_epoch_blocks),
            status: RedactionStatus::Applied,
        };
        self.compliance_redactions
            .insert(redaction_id.clone(), redaction);
        self.counters.compliance_redactions = self.counters.compliance_redactions.saturating_add(1);
        self.push_event(
            RuntimeEventKind::RedactionApplied,
            &redaction_id,
            json!({"subject_id":subject_id}),
        );
        self.recompute_roots();
        Ok(redaction_id)
    }
    pub fn publish_operator_summary(
        &mut self,
        audience: SummaryAudience,
        epoch: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator summaries",
        )?;
        let low_fee_batch_count = self
            .settlement_batches
            .values()
            .filter(|batch| batch.is_low_fee(&self.config))
            .count() as u64;
        let batch_count = self.settlement_batches.len() as u64;
        let total_fee_bps: u64 = self
            .settlement_batches
            .values()
            .map(|batch| batch.fee_bps)
            .sum();
        let average_fee_bps = if batch_count == 0 {
            0
        } else {
            total_fee_bps / batch_count
        };
        let summary_id = operator_summary_id(
            audience,
            epoch,
            self.current_height,
            self.counters.next_sequence,
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            audience,
            epoch,
            lot_count: self.collateral_lots.len() as u64,
            bid_count: self.sealed_bids.len() as u64,
            selected_bid_count: self.counters.selected_bids,
            settled_lot_count: self.counters.settled_lots,
            low_fee_batch_count,
            average_fee_bps,
            haircut_commitment_root: self.roots.haircut_attestation_root.clone(),
            liquidity_commitment_root: self.roots.liquidity_root.clone(),
            compliance_redaction_root: self.roots.compliance_redaction_root.clone(),
            published_at_height: self.current_height,
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.push_event(
            RuntimeEventKind::SummaryPublished,
            &summary_id,
            json!({"audience":audience}),
        );
        self.recompute_roots();
        Ok(summary_id)
    }
    pub fn low_fee_clearable_lots(&self) -> Vec<&RwaCollateralLot> {
        self.collateral_lots
            .values()
            .filter(|lot| {
                lot.selected_bid_id.is_some() && matches!(lot.status, CollateralLotStatus::Clearing)
            })
            .collect()
    }
    pub fn bidder_rebate_ids(&self, bidder_commitment_id: &str) -> Vec<String> {
        self.fee_rebates
            .values()
            .filter(|rebate| rebate.bidder_commitment_id == bidder_commitment_id)
            .map(|rebate| rebate.rebate_id.clone())
            .collect()
    }
    pub fn lot_bid_ids(&self, lot_id: &str) -> Vec<String> {
        self.collateral_lots
            .get(lot_id)
            .map(|lot| lot.bid_ids.iter().cloned().collect())
            .unwrap_or_default()
    }
    pub fn lot_attestation_ids(&self, lot_id: &str) -> Vec<String> {
        self.collateral_lots
            .get(lot_id)
            .map(|lot| lot.attestation_ids.iter().cloned().collect())
            .unwrap_or_default()
    }
    pub fn recompute_roots(&mut self) {
        self.roots.collateral_lot_root = map_root(
            "PRIVATE-L2-RWA-COLLATERAL-LOT",
            &self.collateral_lots,
            RwaCollateralLot::public_record,
        );
        self.roots.sealed_bid_root = map_root(
            "PRIVATE-L2-RWA-SEALED-BID",
            &self.sealed_bids,
            SealedLiquidationBid::public_record,
        );
        self.roots.bidder_commitment_root = map_root(
            "PRIVATE-L2-RWA-BIDDER-COMMITMENT",
            &self.bidder_commitments,
            PrivateBidderCommitment::public_record,
        );
        self.roots.haircut_attestation_root = map_root(
            "PRIVATE-L2-RWA-HAIRCUT-ATTESTATION",
            &self.haircut_attestations,
            OracleHaircutAttestation::public_record,
        );
        self.roots.settlement_batch_root = map_root(
            "PRIVATE-L2-RWA-SETTLEMENT-BATCH",
            &self.settlement_batches,
            SettlementBatch::public_record,
        );
        self.roots.fee_rebate_root = map_root(
            "PRIVATE-L2-RWA-FEE-REBATE",
            &self.fee_rebates,
            FeeRebate::public_record,
        );
        self.roots.compliance_redaction_root = map_root(
            "PRIVATE-L2-RWA-COMPLIANCE-REDACTION",
            &self.compliance_redactions,
            ComplianceRedaction::public_record,
        );
        self.roots.operator_summary_root = map_root(
            "PRIVATE-L2-RWA-OPERATOR-SUMMARY",
            &self.operator_summaries,
            OperatorSummary::public_record,
        );
        self.roots.nullifier_root = set_root("PRIVATE-L2-RWA-NULLIFIER", &self.nullifiers);
        self.roots.event_root = value_root(
            "PRIVATE-L2-RWA-EVENT",
            self.events
                .iter()
                .map(RuntimeEvent::public_record)
                .collect(),
        );
        self.roots.liquidity_root=value_root("PRIVATE-L2-RWA-LIQUIDITY",self.sealed_bids.values().map(|bid|json!({"bid_id":bid.bid_id,"fee_limit_bps":bid.fee_limit_bps,"funding_proof_root":bid.funding_proof_root})).collect());
        self.roots.clearance_root=value_root("PRIVATE-L2-RWA-CLEARANCE",self.settlement_batches.values().map(|batch|json!({"batch_id":batch.batch_id,"lot_ids":batch.lot_ids,"selected_bid_ids":batch.selected_bid_ids,"fee_bps":batch.fee_bps})).collect());
        self.roots.state_root = value_root(
            "PRIVATE-L2-RWA-STATE",
            vec![
                json!({"protocol_version":self.config.protocol_version,"schema_version":self.config.schema_version,"current_height":self.current_height,"counters":self.counters,"collateral_lot_root":self.roots.collateral_lot_root,"sealed_bid_root":self.roots.sealed_bid_root,"bidder_commitment_root":self.roots.bidder_commitment_root,"haircut_attestation_root":self.roots.haircut_attestation_root,"settlement_batch_root":self.roots.settlement_batch_root,"fee_rebate_root":self.roots.fee_rebate_root,"compliance_redaction_root":self.roots.compliance_redaction_root,"operator_summary_root":self.roots.operator_summary_root,"nullifier_root":self.roots.nullifier_root,"event_root":self.roots.event_root,"liquidity_root":self.roots.liquidity_root,"clearance_root":self.roots.clearance_root}),
            ],
        );
    }
    fn expire_stale_records(&mut self) {
        for lot in self.collateral_lots.values_mut() {
            if lot.is_expired(self.current_height) {
                lot.status = CollateralLotStatus::Expired;
            }
        }
        for bid in self.sealed_bids.values_mut() {
            if bid.is_expired(self.current_height) {
                bid.status = BidStatus::Expired;
            }
        }
        for attestation in self.haircut_attestations.values_mut() {
            if attestation.stale_after_height < self.current_height
                && attestation.status.counts_for_quorum()
            {
                attestation.status = AttestationStatus::Expired;
            }
        }
    }
    fn push_event(&mut self, kind: RuntimeEventKind, subject_id: &str, payload: Value) {
        let payload_root = public_record_root(&payload);
        let id = runtime_event_id(
            kind,
            subject_id,
            &payload_root,
            self.current_height,
            self.events.len() as u64,
        );
        self.events.push(RuntimeEvent {
            event_id: id,
            kind,
            subject_id: subject_id.to_string(),
            payload_root,
            height: self.current_height,
        });
    }
}
pub fn devnet() -> State {
    State::devnet()
}
pub fn demo() -> State {
    let mut state = State::devnet();
    let _ = state.advance_height(state.current_height.saturating_add(4));
    let _ = state.publish_operator_summary(SummaryAudience::Public, 1);
    state
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-RWA-LIQUIDATION-AUCTION-PUBLIC-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn collateral_lot_id(
    vault_id: &str,
    borrower_commitment: &str,
    collateral_token_commitment: &str,
    opened_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-COLLATERAL-LOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(vault_id),
            HashPart::Str(borrower_commitment),
            HashPart::Str(collateral_token_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
pub fn collateral_lot_nullifier(
    vault_id: &str,
    borrower_commitment: &str,
    collateral_token_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-COLLATERAL-LOT-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(vault_id),
            HashPart::Str(borrower_commitment),
            HashPart::Str(collateral_token_commitment),
        ],
        32,
    )
}
pub fn bidder_commitment_id(
    bidder_group_root: &str,
    kyc_attestation_root: &str,
    funding_commitment_root: &str,
    opened_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-BIDDER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bidder_group_root),
            HashPart::Str(kyc_attestation_root),
            HashPart::Str(funding_commitment_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
pub fn sealed_bid_id(
    lot_id: &str,
    bidder_commitment_id: &str,
    bid_ciphertext_hash: &str,
    submitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-SEALED-LIQUIDATION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lot_id),
            HashPart::Str(bidder_commitment_id),
            HashPart::Str(bid_ciphertext_hash),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
pub fn bid_nullifier(
    lot_id: &str,
    bidder_commitment_id: &str,
    bid_ciphertext_hash: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-BID-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lot_id),
            HashPart::Str(bidder_commitment_id),
            HashPart::Str(bid_ciphertext_hash),
        ],
        32,
    )
}
pub fn haircut_attestation_id(
    lot_id: &str,
    oracle_set_root: &str,
    price_source_root: &str,
    haircut_bps: u64,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-HAIRCUT-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lot_id),
            HashPart::Str(oracle_set_root),
            HashPart::Str(price_source_root),
            HashPart::Int(haircut_bps as i128),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}
pub fn settlement_batch_id(
    lot_ids: &BTreeSet<String>,
    selected_bid_ids: &BTreeSet<String>,
    clearing_price_root: &str,
    opened_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&json!({"lot_ids":lot_ids})),
            HashPart::Json(&json!({"selected_bid_ids":selected_bid_ids})),
            HashPart::Str(clearing_price_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
pub fn fee_rebate_id(
    batch_id: &str,
    bid_id: &str,
    bidder_commitment_id: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(bid_id),
            HashPart::Str(bidder_commitment_id),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}
pub fn compliance_redaction_id(
    subject_kind: &str,
    subject_id: &str,
    redacted_fields_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-COMPLIANCE-REDACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(redacted_fields_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}
pub fn operator_summary_id(
    audience: SummaryAudience,
    epoch: u64,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(summary_audience_str(audience)),
            HashPart::Int(epoch as i128),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
pub fn runtime_event_id(
    kind: RuntimeEventKind,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    index: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-RUNTIME-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(runtime_event_kind_str(kind)),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
            HashPart::Int(index as i128),
        ],
        32,
    )
}
pub fn fee_units(amount_units: u64, fee_bps: u64) -> u64 {
    amount_units.saturating_mul(fee_bps) / MAX_BPS
}
pub fn coverage_bps(bid_units: u64, reserve_units: u64) -> u64 {
    if reserve_units == 0 {
        return MAX_BPS * 10;
    }
    bid_units.saturating_mul(MAX_BPS) / reserve_units
}
pub fn discounted_units(amount_units: u64, discount_bps: u64) -> u64 {
    amount_units.saturating_sub(fee_units(amount_units, discount_bps.min(MAX_BPS)))
}
fn summary_audience_str(audience: SummaryAudience) -> &'static str {
    match audience {
        SummaryAudience::Operator => "operator",
        SummaryAudience::Liquidator => "liquidator",
        SummaryAudience::Oracle => "oracle",
        SummaryAudience::Compliance => "compliance",
        SummaryAudience::Sponsor => "sponsor",
        SummaryAudience::Public => "public",
    }
}
fn runtime_event_kind_str(kind: RuntimeEventKind) -> &'static str {
    match kind {
        RuntimeEventKind::LotRegistered => "lot_registered",
        RuntimeEventKind::LotHaircutAttested => "lot_haircut_attested",
        RuntimeEventKind::BidCommitted => "bid_committed",
        RuntimeEventKind::BidSelected => "bid_selected",
        RuntimeEventKind::BatchOpened => "batch_opened",
        RuntimeEventKind::BatchCleared => "batch_cleared",
        RuntimeEventKind::RebateIssued => "rebate_issued",
        RuntimeEventKind::RedactionApplied => "redaction_applied",
        RuntimeEventKind::SummaryPublished => "summary_published",
        RuntimeEventKind::NullifierObserved => "nullifier_observed",
    }
}
fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}
fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} bps exceeds {MAX_BPS}"));
    }
    Ok(())
}
fn ensure_fee(fee_bps: u64, max_fee_bps: u64) -> Result<()> {
    if fee_bps > max_fee_bps {
        return Err(format!("fee {fee_bps} bps exceeds max {max_fee_bps} bps"));
    }
    Ok(())
}
fn ensure_privacy_set(size: u64, config: &Config) -> Result<()> {
    if size < config.min_privacy_set_size {
        return Err("privacy set below minimum".to_string());
    }
    Ok(())
}
fn ensure_pq_security(envelope: &PqAttestationEnvelope, config: &Config) -> Result<()> {
    if envelope.security_bits < config.min_pq_security_bits {
        return Err("post-quantum attestation security below minimum".to_string());
    }
    Ok(())
}
fn ensure_new_nullifier(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    if nullifiers.contains(nullifier) {
        return Err("duplicate nullifier".to_string());
    }
    Ok(())
}
fn empty_root(domain: &str) -> String {
    merkle_root(domain, &Vec::<Value>::new())
}
fn tagged_root(tag: &str) -> String {
    domain_hash(
        "PRIVATE-L2-RWA-TAGGED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(tag),
        ],
        32,
    )
}
fn value_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}
fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| json!({"key":key,"record":public_record(value)}))
        .collect();
    merkle_root(domain, &leaves)
}
fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set.iter().map(|value| json!({"value":value})).collect();
    merkle_root(domain, &leaves)
}
fn demo_pq(label: &str) -> PqAttestationEnvelope {
    PqAttestationEnvelope {
        scheme: ORACLE_HAIRCUT_ATTESTATION_SCHEME.to_string(),
        signer_commitment: tagged_root(&format!("{label}-signer")),
        public_key_commitment: tagged_root(&format!("{label}-pk")),
        transcript_hash: tagged_root(&format!("{label}-transcript")),
        signature_commitment: tagged_root(&format!("{label}-sig")),
        aggregate_signature_root: tagged_root(&format!("{label}-agg")),
        security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
    }
}
fn seed_devnet(state: &mut State) {
    let bidder_a = state
        .register_bidder_commitment(
            tagged_root("bidder-a-group"),
            tagged_root("bidder-a-kyc"),
            tagged_root("bidder-a-accreditation"),
            tagged_root("bidder-a-sanctions"),
            tagged_root("bidder-a-funding"),
            tagged_root("bidder-a-settlement-address"),
            tagged_root("bidder-a-contact-route"),
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            demo_pq("bidder-a"),
        )
        .expect("devnet bidder a registers");
    let bidder_b = state
        .register_bidder_commitment(
            tagged_root("bidder-b-group"),
            tagged_root("bidder-b-kyc"),
            tagged_root("bidder-b-accreditation"),
            tagged_root("bidder-b-sanctions"),
            tagged_root("bidder-b-funding"),
            tagged_root("bidder-b-settlement-address"),
            tagged_root("bidder-b-contact-route"),
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            demo_pq("bidder-b"),
        )
        .expect("devnet bidder b registers");
    let lot_a = state
        .open_collateral_lot(
            "vault-devnet-rwa-001",
            tagged_root("borrower-a"),
            RwaClass::PrivateCredit,
            tagged_root("collateral-token-a"),
            tagged_root("registry-a"),
            tagged_root("jurisdiction-us-qualified"),
            tagged_root("lien-root-a"),
            tagged_root("valuation-a"),
            tagged_root("debt-a"),
            tagged_root("reserve-price-a"),
            1250,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
        )
        .expect("devnet lot a opens");
    let lot_b = state
        .open_collateral_lot(
            "vault-devnet-rwa-002",
            tagged_root("borrower-b"),
            RwaClass::TreasuryBill,
            tagged_root("collateral-token-b"),
            tagged_root("registry-b"),
            tagged_root("jurisdiction-eu-qualified"),
            tagged_root("lien-root-b"),
            tagged_root("valuation-b"),
            tagged_root("debt-b"),
            tagged_root("reserve-price-b"),
            350,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
        )
        .expect("devnet lot b opens");
    state
        .attest_haircut(
            &lot_a,
            tagged_root("oracle-set-a"),
            tagged_root("price-source-a"),
            tagged_root("valuation-attested-a"),
            2000,
            8800,
            8100,
            500,
            demo_pq("oracle-a"),
        )
        .expect("devnet haircut a attests");
    state
        .attest_haircut(
            &lot_b,
            tagged_root("oracle-set-b"),
            tagged_root("price-source-b"),
            tagged_root("valuation-attested-b"),
            300,
            9200,
            8400,
            100,
            demo_pq("oracle-b"),
        )
        .expect("devnet haircut b attests");
    let bid_a = state
        .submit_sealed_bid(
            &lot_a,
            &bidder_a,
            tagged_root("bid-a-ciphertext"),
            tagged_root("bid-a-price"),
            4500,
            DEFAULT_LOW_FEE_BATCH_BPS,
            tagged_root("bid-a-settlement-asset"),
            tagged_root("bid-a-funding-proof"),
            tagged_root("bid-a-rebate"),
            tagged_root("bid-a-compliance"),
            demo_pq("bid-a"),
        )
        .expect("devnet bid a submits");
    let bid_b = state
        .submit_sealed_bid(
            &lot_b,
            &bidder_b,
            tagged_root("bid-b-ciphertext"),
            tagged_root("bid-b-price"),
            900,
            DEFAULT_LOW_FEE_BATCH_BPS,
            tagged_root("bid-b-settlement-asset"),
            tagged_root("bid-b-funding-proof"),
            tagged_root("bid-b-rebate"),
            tagged_root("bid-b-compliance"),
            demo_pq("bid-b"),
        )
        .expect("devnet bid b submits");
    state
        .select_bid(&lot_a, &bid_a)
        .expect("devnet selects bid a");
    state
        .select_bid(&lot_b, &bid_b)
        .expect("devnet selects bid b");
    let mut lot_ids = BTreeSet::new();
    lot_ids.insert(lot_a.clone());
    lot_ids.insert(lot_b.clone());
    let batch = state
        .open_settlement_batch(
            lot_ids,
            tagged_root("batch-settlement-asset"),
            tagged_root("batch-clearing-price"),
            tagged_root("batch-transfer-manifest"),
            tagged_root("batch-compliance-manifest"),
            tagged_root("batch-fee"),
            DEFAULT_LOW_FEE_BATCH_BPS,
            tagged_root("batch-rebate-pool"),
            tagged_root("batch-low-fee-sponsor"),
            tagged_root("batch-netting"),
        )
        .expect("devnet batch opens");
    state
        .finalize_settlement_batch(&batch)
        .expect("devnet batch finalizes");
    state
        .issue_fee_rebate(
            &batch,
            &bid_a,
            tagged_root("rebate-a"),
            tagged_root("sponsor-a"),
            tagged_root("fee-paid-a"),
            tagged_root("eligibility-a"),
        )
        .expect("devnet rebate a issues");
    state
        .issue_fee_rebate(
            &batch,
            &bid_b,
            tagged_root("rebate-b"),
            tagged_root("sponsor-b"),
            tagged_root("fee-paid-b"),
            tagged_root("eligibility-b"),
        )
        .expect("devnet rebate b issues");
    state
        .apply_compliance_redaction(
            "settlement_batch",
            &batch,
            tagged_root("batch-redacted-fields"),
            SummaryAudience::Compliance,
            tagged_root("regulator-devnet"),
            tagged_root("warrant-devnet"),
            tagged_root("view-key-policy-devnet"),
        )
        .expect("devnet redaction applies");
    state
        .publish_operator_summary(SummaryAudience::Operator, 0)
        .expect("devnet operator summary publishes");
}
impl State {
    pub fn collateral_lot(&self, id: &str) -> Option<&RwaCollateralLot> {
        self.collateral_lots.get(id)
    }
    pub fn collateral_lot_record(&self, id: &str) -> Option<Value> {
        self.collateral_lots
            .get(id)
            .map(RwaCollateralLot::public_record)
    }
    pub fn collateral_lot_ids(&self) -> Vec<String> {
        self.collateral_lots.keys().cloned().collect()
    }
}
impl State {
    pub fn sealed_bid(&self, id: &str) -> Option<&SealedLiquidationBid> {
        self.sealed_bids.get(id)
    }
    pub fn sealed_bid_record(&self, id: &str) -> Option<Value> {
        self.sealed_bids
            .get(id)
            .map(SealedLiquidationBid::public_record)
    }
    pub fn sealed_bid_ids(&self) -> Vec<String> {
        self.sealed_bids.keys().cloned().collect()
    }
}
impl State {
    pub fn bidder_commitment(&self, id: &str) -> Option<&PrivateBidderCommitment> {
        self.bidder_commitments.get(id)
    }
    pub fn bidder_commitment_record(&self, id: &str) -> Option<Value> {
        self.bidder_commitments
            .get(id)
            .map(PrivateBidderCommitment::public_record)
    }
    pub fn bidder_commitment_ids(&self) -> Vec<String> {
        self.bidder_commitments.keys().cloned().collect()
    }
}
impl State {
    pub fn haircut_attestation(&self, id: &str) -> Option<&OracleHaircutAttestation> {
        self.haircut_attestations.get(id)
    }
    pub fn haircut_attestation_record(&self, id: &str) -> Option<Value> {
        self.haircut_attestations
            .get(id)
            .map(OracleHaircutAttestation::public_record)
    }
    pub fn haircut_attestation_ids(&self) -> Vec<String> {
        self.haircut_attestations.keys().cloned().collect()
    }
}
impl State {
    pub fn settlement_batch(&self, id: &str) -> Option<&SettlementBatch> {
        self.settlement_batches.get(id)
    }
    pub fn settlement_batch_record(&self, id: &str) -> Option<Value> {
        self.settlement_batches
            .get(id)
            .map(SettlementBatch::public_record)
    }
    pub fn settlement_batch_ids(&self) -> Vec<String> {
        self.settlement_batches.keys().cloned().collect()
    }
}
impl State {
    pub fn fee_rebate(&self, id: &str) -> Option<&FeeRebate> {
        self.fee_rebates.get(id)
    }
    pub fn fee_rebate_record(&self, id: &str) -> Option<Value> {
        self.fee_rebates.get(id).map(FeeRebate::public_record)
    }
    pub fn fee_rebate_ids(&self) -> Vec<String> {
        self.fee_rebates.keys().cloned().collect()
    }
}
impl State {
    pub fn compliance_redaction(&self, id: &str) -> Option<&ComplianceRedaction> {
        self.compliance_redactions.get(id)
    }
    pub fn compliance_redaction_record(&self, id: &str) -> Option<Value> {
        self.compliance_redactions
            .get(id)
            .map(ComplianceRedaction::public_record)
    }
    pub fn compliance_redaction_ids(&self) -> Vec<String> {
        self.compliance_redactions.keys().cloned().collect()
    }
}
impl State {
    pub fn operator_summary(&self, id: &str) -> Option<&OperatorSummary> {
        self.operator_summaries.get(id)
    }
    pub fn operator_summary_record(&self, id: &str) -> Option<Value> {
        self.operator_summaries
            .get(id)
            .map(OperatorSummary::public_record)
    }
    pub fn operator_summary_ids(&self) -> Vec<String> {
        self.operator_summaries.keys().cloned().collect()
    }
}
