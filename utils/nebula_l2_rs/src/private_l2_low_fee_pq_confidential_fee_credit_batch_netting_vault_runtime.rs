use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialFeeCreditBatchNettingVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_CREDIT_BATCH_NETTING_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-credit-batch-netting-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_CREDIT_BATCH_NETTING_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-fee-credit-netting-v1";
pub const CONFIDENTIAL_FEE_CREDIT_SCHEME: &str = "ringct-style-low-fee-credit-ledger-commitment-v1";
pub const BATCH_NETTING_SCHEME: &str = "pq-confidential-fee-credit-batch-netting-epoch-v1";
pub const SPONSOR_COMMITMENT_SCHEME: &str =
    "pq-confidential-sponsor-fee-credit-vault-commitment-v1";
pub const SETTLEMENT_VOUCHER_SCHEME: &str =
    "pq-confidential-fee-credit-netted-settlement-voucher-v1";
pub const ABUSE_THROTTLE_SCHEME: &str = "operator-safe-fee-credit-abuse-throttle-root-v1";
pub const REBATE_DISTRIBUTION_SCHEME: &str = "redacted-fee-credit-rebate-distribution-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "confidential-fee-credit-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-low-fee-netting-summary-root-v1";
pub const DEVNET_CHAIN_ID: u64 = 731_337;
pub const DEVNET_HEIGHT: u64 = 2_486_000;
pub const DEVNET_EPOCH: u64 = 7_104;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_CREDIT_ASSET: &str = "confidential-fee-credit-devnet";
pub const DEVNET_SETTLEMENT_ASSET: &str = "piconero-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 360;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_ABUSE_WINDOW_BLOCKS: u64 = 180;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 2_880;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_THROTTLE_SCORE_LIMIT: u64 = 10_000;
pub const DEFAULT_MAX_REDACTION_UNITS: u64 = 1_024;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_LEDGERS: usize = 1_048_576;
pub const MAX_EPOCHS: usize = 524_288;
pub const MAX_SPONSORS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_VOUCHERS: usize = 4_194_304;
pub const MAX_THROTTLES: usize = 1_048_576;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCreditLane {
    PrivateTransfer,
    ContractCall,
    BatchSwap,
    BridgeExit,
    ProofAggregation,
    MerchantMicroPayment,
    OracleUpdate,
    StateRentCompression,
    EmergencyExit,
}

impl FeeCreditLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::BatchSwap => "batch_swap",
            Self::BridgeExit => "bridge_exit",
            Self::ProofAggregation => "proof_aggregation",
            Self::MerchantMicroPayment => "merchant_micro_payment",
            Self::OracleUpdate => "oracle_update",
            Self::StateRentCompression => "state_rent_compression",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::BridgeExit => 8_600,
            Self::BatchSwap => 7_400,
            Self::ContractCall => 6_800,
            Self::ProofAggregation => 5_600,
            Self::PrivateTransfer => 5_200,
            Self::MerchantMicroPayment => 4_700,
            Self::OracleUpdate => 4_100,
            Self::StateRentCompression => 3_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerStatus {
    Open,
    Reserved,
    Netted,
    Settled,
    Rebated,
    Suspended,
    Exhausted,
}

impl LedgerStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Rebated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Draft,
    Open,
    Sealed,
    Netted,
    Voucherized,
    Settled,
    Disputed,
    Expired,
}

impl EpochStatus {
    pub fn accepts_ledgers(self) -> bool {
        matches!(self, Self::Draft | Self::Open)
    }

    pub fn accepts_vouchers(self) -> bool {
        matches!(self, Self::Netted | Self::Voucherized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Registered,
    Active,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl SponsorStatus {
    pub fn covers(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPurpose {
    LedgerFunding,
    EpochEligibility,
    SponsorSolvency,
    NettingCorrectness,
    VoucherSettlement,
    AbuseReview,
    RedactionDisclosure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Proposed,
    Attested,
    Submitted,
    Settled,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseThrottleStatus {
    Observing,
    Throttled,
    Quarantined,
    Released,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Allocated,
    Voucherized,
    Distributed,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    OperatorSummary,
    SponsorAudit,
    VoucherReview,
    AbuseAppeal,
    RegulatoryExport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_credit_asset: String,
    pub settlement_asset: String,
    pub epoch_blocks: u64,
    pub settlement_window_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub abuse_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub throttle_score_limit: u64,
    pub max_redaction_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_credit_asset: DEVNET_FEE_CREDIT_ASSET.to_string(),
            settlement_asset: DEVNET_SETTLEMENT_ASSET.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            abuse_window_blocks: DEFAULT_ABUSE_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            throttle_score_limit: DEFAULT_THROTTLE_SCORE_LIMIT,
            max_redaction_units: DEFAULT_MAX_REDACTION_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.chain_id > 0, "chain_id must be nonzero");
        ensure!(!self.l2_network.is_empty(), "l2_network must be set");
        ensure!(
            !self.fee_credit_asset.is_empty(),
            "fee_credit_asset must be set"
        );
        ensure!(self.epoch_blocks > 0, "epoch_blocks must be nonzero");
        ensure!(
            self.settlement_window_blocks > 0,
            "settlement_window_blocks must be nonzero"
        );
        ensure!(
            self.min_pq_security_bits >= 128,
            "min_pq_security_bits is below policy"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS,
            "max_user_fee_bps exceeds MAX_BPS"
        );
        ensure!(
            self.target_rebate_bps <= MAX_BPS,
            "target_rebate_bps exceeds MAX_BPS"
        );
        ensure!(
            self.sponsor_reserve_bps <= MAX_BPS,
            "sponsor_reserve_bps exceeds MAX_BPS"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_credit_asset": self.fee_credit_asset,
            "settlement_asset": self.settlement_asset,
            "epoch_blocks": self.epoch_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "abuse_window_blocks": self.abuse_window_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "throttle_score_limit": self.throttle_score_limit,
            "max_redaction_units": self.max_redaction_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub ledgers_opened: u64,
    pub ledgers_netted: u64,
    pub epochs_opened: u64,
    pub epochs_sealed: u64,
    pub sponsor_commitments_registered: u64,
    pub pq_attestations_recorded: u64,
    pub settlement_vouchers_issued: u64,
    pub settlement_vouchers_settled: u64,
    pub abuse_throttles_opened: u64,
    pub rebates_distributed: u64,
    pub redaction_budgets_issued: u64,
    pub operator_summaries_published: u64,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "ledgers_opened": self.ledgers_opened,
            "ledgers_netted": self.ledgers_netted,
            "epochs_opened": self.epochs_opened,
            "epochs_sealed": self.epochs_sealed,
            "sponsor_commitments_registered": self.sponsor_commitments_registered,
            "pq_attestations_recorded": self.pq_attestations_recorded,
            "settlement_vouchers_issued": self.settlement_vouchers_issued,
            "settlement_vouchers_settled": self.settlement_vouchers_settled,
            "abuse_throttles_opened": self.abuse_throttles_opened,
            "rebates_distributed": self.rebates_distributed,
            "redaction_budgets_issued": self.redaction_budgets_issued,
            "operator_summaries_published": self.operator_summaries_published,
            "events_emitted": self.events_emitted,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub ledgers_root: String,
    pub epochs_root: String,
    pub sponsor_commitments_root: String,
    pub pq_attestations_root: String,
    pub settlement_vouchers_root: String,
    pub abuse_throttles_root: String,
    pub rebate_distributions_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub indexes_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "ledgers_root": self.ledgers_root,
            "epochs_root": self.epochs_root,
            "sponsor_commitments_root": self.sponsor_commitments_root,
            "pq_attestations_root": self.pq_attestations_root,
            "settlement_vouchers_root": self.settlement_vouchers_root,
            "abuse_throttles_root": self.abuse_throttles_root,
            "rebate_distributions_root": self.rebate_distributions_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "indexes_root": self.indexes_root,
            "events_root": self.events_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCreditLedger {
    pub ledger_id: String,
    pub owner_commitment: String,
    pub lane: FeeCreditLane,
    pub status: LedgerStatus,
    pub epoch_id: String,
    pub sponsor_id: String,
    pub confidential_credit_commitment: String,
    pub debited_fee_commitment: String,
    pub netted_fee_commitment: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl FeeCreditLedger {
    pub fn new(
        config: &Config,
        epoch_id: impl Into<String>,
        sponsor_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        lane: FeeCreditLane,
        nonce: u64,
    ) -> Self {
        let epoch_id = epoch_id.into();
        let sponsor_id = sponsor_id.into();
        let owner_commitment = owner_commitment.into();
        let ledger_id = ledger_id(&epoch_id, &owner_commitment, lane, nonce);
        let confidential_credit_commitment = commitment(
            "LEDGER-CREDIT",
            &[
                &ledger_id,
                &owner_commitment,
                CONFIDENTIAL_FEE_CREDIT_SCHEME,
            ],
        );
        let debited_fee_commitment = commitment("LEDGER-DEBIT", &[&ledger_id, lane.as_str()]);
        let netted_fee_commitment = commitment("LEDGER-NETTED", &[&ledger_id, &sponsor_id]);
        let nullifier_root = commitment("LEDGER-NULLIFIERS", &[&ledger_id, &epoch_id]);
        Self {
            ledger_id,
            owner_commitment,
            lane,
            status: LedgerStatus::Open,
            epoch_id,
            sponsor_id,
            confidential_credit_commitment,
            debited_fee_commitment,
            netted_fee_commitment,
            nullifier_root,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            max_user_fee_bps: config.max_user_fee_bps,
            opened_at_height: DEVNET_HEIGHT,
            updated_at_height: DEVNET_HEIGHT,
        }
    }

    pub fn net(&mut self, height: u64) -> Result<()> {
        ensure!(
            self.status.spendable(),
            "ledger {} is not spendable",
            self.ledger_id
        );
        self.status = LedgerStatus::Netted;
        self.updated_at_height = height;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ledger_id": self.ledger_id,
            "owner_commitment": self.owner_commitment,
            "lane": self.lane.as_str(),
            "status": self.status,
            "epoch_id": self.epoch_id,
            "sponsor_id": self.sponsor_id,
            "confidential_credit_commitment": self.confidential_credit_commitment,
            "debited_fee_commitment": self.debited_fee_commitment,
            "netted_fee_commitment": self.netted_fee_commitment,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchNettingEpoch {
    pub epoch_id: String,
    pub epoch_number: u64,
    pub status: EpochStatus,
    pub lanes: BTreeSet<FeeCreditLane>,
    pub ledger_count: u64,
    pub sponsor_count: u64,
    pub gross_fee_commitment_root: String,
    pub net_fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub settlement_voucher_root: String,
    pub start_height: u64,
    pub seal_height: u64,
    pub settlement_deadline_height: u64,
}

impl BatchNettingEpoch {
    pub fn new(config: &Config, epoch_number: u64, lanes: BTreeSet<FeeCreditLane>) -> Self {
        let epoch_id = epoch_id(epoch_number, DEVNET_HEIGHT);
        let gross_fee_commitment_root =
            commitment("EPOCH-GROSS-FEES", &[&epoch_id, BATCH_NETTING_SCHEME]);
        let net_fee_commitment_root = commitment("EPOCH-NET-FEES", &[&epoch_id]);
        let rebate_commitment_root = commitment("EPOCH-REBATES", &[&epoch_id]);
        let settlement_voucher_root = commitment("EPOCH-VOUCHERS", &[&epoch_id]);
        Self {
            epoch_id,
            epoch_number,
            status: EpochStatus::Open,
            lanes,
            ledger_count: 0,
            sponsor_count: 0,
            gross_fee_commitment_root,
            net_fee_commitment_root,
            rebate_commitment_root,
            settlement_voucher_root,
            start_height: DEVNET_HEIGHT,
            seal_height: DEVNET_HEIGHT.saturating_add(config.epoch_blocks),
            settlement_deadline_height: DEVNET_HEIGHT
                .saturating_add(config.epoch_blocks)
                .saturating_add(config.settlement_window_blocks),
        }
    }

    pub fn seal(&mut self, ledger_count: u64, sponsor_count: u64) -> Result<()> {
        ensure!(
            self.status.accepts_ledgers(),
            "epoch {} does not accept sealing",
            self.epoch_id
        );
        self.status = EpochStatus::Sealed;
        self.ledger_count = ledger_count;
        self.sponsor_count = sponsor_count;
        Ok(())
    }

    pub fn mark_netted(&mut self, voucher_root: impl Into<String>) -> Result<()> {
        ensure!(
            self.status == EpochStatus::Sealed,
            "epoch must be sealed before netting"
        );
        self.status = EpochStatus::Netted;
        self.settlement_voucher_root = voucher_root.into();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "epoch_number": self.epoch_number,
            "status": self.status,
            "lanes": self.lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "ledger_count": self.ledger_count,
            "sponsor_count": self.sponsor_count,
            "gross_fee_commitment_root": self.gross_fee_commitment_root,
            "net_fee_commitment_root": self.net_fee_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "settlement_voucher_root": self.settlement_voucher_root,
            "start_height": self.start_height,
            "seal_height": self.seal_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCommitment {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: SponsorStatus,
    pub lanes: BTreeSet<FeeCreditLane>,
    pub confidential_capacity_commitment: String,
    pub reserve_commitment: String,
    pub policy_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SponsorCommitment {
    pub fn new(
        config: &Config,
        sponsor_commitment: impl Into<String>,
        lanes: BTreeSet<FeeCreditLane>,
        nonce: u64,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let sponsor_id = sponsor_id(&sponsor_commitment, nonce);
        let lane_weight = lanes.iter().map(|lane| lane.weight()).sum::<u64>();
        let confidential_capacity_commitment = commitment(
            "SPONSOR-CAPACITY",
            &[&sponsor_id, SPONSOR_COMMITMENT_SCHEME],
        );
        let reserve_commitment = commitment("SPONSOR-RESERVE", &[&sponsor_id]);
        let policy_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:SPONSOR-POLICY",
            &[
                HashPart::Str(&sponsor_id),
                HashPart::U64(lane_weight),
                HashPart::U64(config.sponsor_reserve_bps),
            ],
            32,
        );
        Self {
            sponsor_id,
            sponsor_commitment,
            status: SponsorStatus::Active,
            lanes,
            confidential_capacity_commitment,
            reserve_commitment,
            policy_root,
            pq_security_bits: config.min_pq_security_bits,
            privacy_set_size: config.target_privacy_set_size,
            max_fee_bps: config.max_user_fee_bps,
            rebate_bps: config.target_rebate_bps,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.sponsor_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status,
            "lanes": self.lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "confidential_capacity_commitment": self.confidential_capacity_commitment,
            "reserve_commitment": self.reserve_commitment,
            "policy_root": self.policy_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub purpose: AttestationPurpose,
    pub subject_id: String,
    pub signer_committee_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub quorum: u16,
    pub observed_at_height: u64,
}

impl PqAttestation {
    pub fn new(
        config: &Config,
        purpose: AttestationPurpose,
        subject_id: impl Into<String>,
        quorum: u16,
        nonce: u64,
    ) -> Self {
        let subject_id = subject_id.into();
        let attestation_id = attestation_id(purpose, &subject_id, nonce);
        Self {
            signer_committee_root: commitment("ATTESTATION-SIGNERS", &[&attestation_id]),
            transcript_root: commitment("ATTESTATION-TRANSCRIPT", &[&attestation_id, &subject_id]),
            signature_root: commitment(
                "ATTESTATION-SIGNATURES",
                &[&attestation_id, PQ_ATTESTATION_SUITE],
            ),
            pq_security_bits: config.min_pq_security_bits,
            attestation_id,
            purpose,
            subject_id,
            quorum,
            observed_at_height: DEVNET_HEIGHT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "purpose": self.purpose,
            "subject_id": self.subject_id,
            "signer_committee_root": self.signer_committee_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum": self.quorum,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementVoucher {
    pub voucher_id: String,
    pub epoch_id: String,
    pub sponsor_id: String,
    pub status: VoucherStatus,
    pub netted_fee_commitment: String,
    pub settlement_asset_commitment: String,
    pub rebate_commitment: String,
    pub attestation_root: String,
    pub nullifier_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementVoucher {
    pub fn new(
        config: &Config,
        epoch_id: impl Into<String>,
        sponsor_id: impl Into<String>,
        attestation_root: impl Into<String>,
        nonce: u64,
    ) -> Self {
        let epoch_id = epoch_id.into();
        let sponsor_id = sponsor_id.into();
        let voucher_id = voucher_id(&epoch_id, &sponsor_id, nonce);
        Self {
            netted_fee_commitment: commitment("VOUCHER-NETTED-FEE", &[&voucher_id]),
            settlement_asset_commitment: commitment(
                "VOUCHER-SETTLEMENT-ASSET",
                &[&voucher_id, &config.settlement_asset],
            ),
            rebate_commitment: commitment("VOUCHER-REBATE", &[&voucher_id]),
            nullifier_root: commitment("VOUCHER-NULLIFIERS", &[&voucher_id]),
            attestation_root: attestation_root.into(),
            issued_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.voucher_ttl_blocks),
            voucher_id,
            epoch_id,
            sponsor_id,
            status: VoucherStatus::Attested,
        }
    }

    pub fn settle(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.status,
                VoucherStatus::Attested | VoucherStatus::Submitted
            ),
            "voucher {} cannot settle from {:?}",
            self.voucher_id,
            self.status
        );
        self.status = VoucherStatus::Settled;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "epoch_id": self.epoch_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "netted_fee_commitment": self.netted_fee_commitment,
            "settlement_asset_commitment": self.settlement_asset_commitment,
            "rebate_commitment": self.rebate_commitment,
            "attestation_root": self.attestation_root,
            "nullifier_root": self.nullifier_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AbuseThrottle {
    pub throttle_id: String,
    pub subject_commitment: String,
    pub status: AbuseThrottleStatus,
    pub score_commitment: String,
    pub score_limit: u64,
    pub reason_root: String,
    pub decay_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl AbuseThrottle {
    pub fn new(config: &Config, subject_commitment: impl Into<String>, nonce: u64) -> Self {
        let subject_commitment = subject_commitment.into();
        let throttle_id = throttle_id(&subject_commitment, nonce);
        Self {
            score_commitment: commitment("THROTTLE-SCORE", &[&throttle_id, ABUSE_THROTTLE_SCHEME]),
            reason_root: commitment("THROTTLE-REASONS", &[&throttle_id]),
            decay_root: commitment("THROTTLE-DECAY", &[&throttle_id]),
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.abuse_window_blocks),
            throttle_id,
            subject_commitment,
            status: AbuseThrottleStatus::Observing,
            score_limit: config.throttle_score_limit,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "subject_commitment": self.subject_commitment,
            "status": self.status,
            "score_commitment": self.score_commitment,
            "score_limit": self.score_limit,
            "reason_root": self.reason_root,
            "decay_root": self.decay_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateDistribution {
    pub rebate_id: String,
    pub epoch_id: String,
    pub voucher_id: String,
    pub status: RebateStatus,
    pub recipient_set_root: String,
    pub amount_commitment_root: String,
    pub distribution_proof_root: String,
    pub rebate_bps: u64,
    pub distributed_at_height: u64,
}

impl RebateDistribution {
    pub fn new(
        epoch_id: impl Into<String>,
        voucher_id: impl Into<String>,
        rebate_bps: u64,
        nonce: u64,
    ) -> Self {
        let epoch_id = epoch_id.into();
        let voucher_id = voucher_id.into();
        let rebate_id = rebate_id(&epoch_id, &voucher_id, nonce);
        Self {
            recipient_set_root: commitment("REBATE-RECIPIENTS", &[&rebate_id]),
            amount_commitment_root: commitment(
                "REBATE-AMOUNTS",
                &[&rebate_id, REBATE_DISTRIBUTION_SCHEME],
            ),
            distribution_proof_root: commitment("REBATE-PROOF", &[&rebate_id]),
            distributed_at_height: DEVNET_HEIGHT,
            rebate_id,
            epoch_id,
            voucher_id,
            status: RebateStatus::Distributed,
            rebate_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "epoch_id": self.epoch_id,
            "voucher_id": self.voucher_id,
            "status": self.status,
            "recipient_set_root": self.recipient_set_root,
            "amount_commitment_root": self.amount_commitment_root,
            "distribution_proof_root": self.distribution_proof_root,
            "rebate_bps": self.rebate_bps,
            "distributed_at_height": self.distributed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub scope: RedactionScope,
    pub subject_id: String,
    pub disclosure_root: String,
    pub remaining_units: u64,
    pub max_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn new(
        config: &Config,
        scope: RedactionScope,
        subject_id: impl Into<String>,
        units: u64,
        nonce: u64,
    ) -> Self {
        let subject_id = subject_id.into();
        let max_units = units.min(config.max_redaction_units);
        let budget_id = redaction_budget_id(scope, &subject_id, nonce);
        Self {
            disclosure_root: commitment(
                "REDACTION-DISCLOSURE",
                &[&budget_id, REDACTION_BUDGET_SCHEME],
            ),
            remaining_units: max_units,
            issued_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.redaction_window_blocks),
            budget_id,
            scope,
            subject_id,
            max_units,
        }
    }

    pub fn spend(&mut self, units: u64) -> Result<()> {
        ensure!(
            self.remaining_units >= units,
            "redaction budget {} exhausted",
            self.budget_id
        );
        self.remaining_units -= units;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "scope": self.scope,
            "subject_id": self.subject_id,
            "disclosure_root": self.disclosure_root,
            "remaining_units": self.remaining_units,
            "max_units": self.max_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub epoch_id: String,
    pub status: EpochStatus,
    pub lane_counts: BTreeMap<String, u64>,
    pub ledger_count: u64,
    pub sponsor_count: u64,
    pub voucher_count: u64,
    pub rebate_count: u64,
    pub throttle_count: u64,
    pub public_commitment_root: String,
    pub redaction_budget_root: String,
    pub generated_at_height: u64,
}

impl OperatorSafeSummary {
    pub fn new(state: &State, epoch_id: impl Into<String>, nonce: u64) -> Self {
        let epoch_id = epoch_id.into();
        let status = state
            .epochs
            .get(&epoch_id)
            .map(|epoch| epoch.status)
            .unwrap_or(EpochStatus::Expired);
        let mut lane_counts = BTreeMap::new();
        for ledger in state
            .ledgers
            .values()
            .filter(|ledger| ledger.epoch_id == epoch_id)
        {
            *lane_counts
                .entry(ledger.lane.as_str().to_string())
                .or_insert(0) += 1;
        }
        let voucher_count = state
            .settlement_vouchers
            .values()
            .filter(|voucher| voucher.epoch_id == epoch_id)
            .count() as u64;
        let rebate_count = state
            .rebate_distributions
            .values()
            .filter(|rebate| rebate.epoch_id == epoch_id)
            .count() as u64;
        let summary_id = operator_summary_id(&epoch_id, nonce);
        Self {
            public_commitment_root: commitment(
                "OPERATOR-SAFE-SUMMARY",
                &[&summary_id, OPERATOR_SUMMARY_SCHEME],
            ),
            redaction_budget_root: state.roots.redaction_budgets_root.clone(),
            generated_at_height: DEVNET_HEIGHT,
            sponsor_count: state.sponsor_commitments.len() as u64,
            throttle_count: state.abuse_throttles.len() as u64,
            ledger_count: lane_counts.values().sum(),
            summary_id,
            epoch_id,
            status,
            lane_counts,
            voucher_count,
            rebate_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "epoch_id": self.epoch_id,
            "status": self.status,
            "lane_counts": self.lane_counts,
            "ledger_count": self.ledger_count,
            "sponsor_count": self.sponsor_count,
            "voucher_count": self.voucher_count,
            "rebate_count": self.rebate_count,
            "throttle_count": self.throttle_count,
            "public_commitment_root": self.public_commitment_root,
            "redaction_budget_root": self.redaction_budget_root,
            "generated_at_height": self.generated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub event_root: String,
    pub height: u64,
}

impl RuntimeEvent {
    pub fn new(kind: impl Into<String>, subject_id: impl Into<String>, nonce: u64) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let event_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:EVENT-ID",
            &[
                HashPart::Str(&kind),
                HashPart::Str(&subject_id),
                HashPart::U64(nonce),
            ],
            32,
        );
        let event_root = commitment("EVENT", &[&event_id, &kind, &subject_id]);
        Self {
            event_id,
            kind,
            subject_id,
            event_root,
            height: DEVNET_HEIGHT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "event_root": self.event_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub ledgers: BTreeMap<String, FeeCreditLedger>,
    pub epochs: BTreeMap<String, BatchNettingEpoch>,
    pub sponsor_commitments: BTreeMap<String, SponsorCommitment>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub settlement_vouchers: BTreeMap<String, SettlementVoucher>,
    pub abuse_throttles: BTreeMap<String, AbuseThrottle>,
    pub rebate_distributions: BTreeMap<String, RebateDistribution>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
    pub ledger_by_epoch: BTreeMap<String, BTreeSet<String>>,
    pub sponsors_by_lane: BTreeMap<String, BTreeSet<String>>,
    pub vouchers_by_epoch: BTreeMap<String, BTreeSet<String>>,
    pub events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            ledgers: BTreeMap::new(),
            epochs: BTreeMap::new(),
            sponsor_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlement_vouchers: BTreeMap::new(),
            abuse_throttles: BTreeMap::new(),
            rebate_distributions: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            ledger_by_epoch: BTreeMap::new(),
            sponsors_by_lane: BTreeMap::new(),
            vouchers_by_epoch: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        let mut lanes = BTreeSet::new();
        lanes.insert(FeeCreditLane::PrivateTransfer);
        lanes.insert(FeeCreditLane::ContractCall);
        lanes.insert(FeeCreditLane::BatchSwap);
        lanes.insert(FeeCreditLane::BridgeExit);
        let epoch = BatchNettingEpoch::new(&state.config, DEVNET_EPOCH, lanes.clone());
        let epoch_id = epoch.epoch_id.clone();
        state.insert_epoch(epoch).expect("devnet epoch");
        let sponsor =
            SponsorCommitment::new(&state.config, "devnet-sponsor-commitment-a", lanes, 1);
        let sponsor_id = sponsor.sponsor_id.clone();
        state
            .insert_sponsor_commitment(sponsor)
            .expect("devnet sponsor commitment");
        state
            .open_ledger(
                &epoch_id,
                &sponsor_id,
                "owner-commitment-alpha",
                FeeCreditLane::PrivateTransfer,
                11,
            )
            .expect("devnet ledger alpha");
        state
            .open_ledger(
                &epoch_id,
                &sponsor_id,
                "owner-commitment-beta",
                FeeCreditLane::ContractCall,
                12,
            )
            .expect("devnet ledger beta");
        state
            .open_ledger(
                &epoch_id,
                &sponsor_id,
                "owner-commitment-gamma",
                FeeCreditLane::BatchSwap,
                13,
            )
            .expect("devnet ledger gamma");
        let funding_attestation = PqAttestation::new(
            &state.config,
            AttestationPurpose::SponsorSolvency,
            &sponsor_id,
            5,
            21,
        );
        state
            .insert_pq_attestation(funding_attestation)
            .expect("devnet sponsor attestation");
        let epoch_attestation = PqAttestation::new(
            &state.config,
            AttestationPurpose::NettingCorrectness,
            &epoch_id,
            7,
            22,
        );
        let attestation_root = epoch_attestation.signature_root.clone();
        state
            .insert_pq_attestation(epoch_attestation)
            .expect("devnet epoch attestation");
        state
            .seal_and_net_epoch(&epoch_id, &attestation_root)
            .expect("devnet netting");
        let voucher =
            SettlementVoucher::new(&state.config, &epoch_id, &sponsor_id, attestation_root, 31);
        let voucher_id = voucher.voucher_id.clone();
        state
            .insert_settlement_voucher(voucher)
            .expect("devnet voucher");
        state
            .settle_voucher(&voucher_id)
            .expect("devnet voucher settlement");
        let rebate =
            RebateDistribution::new(&epoch_id, &voucher_id, state.config.target_rebate_bps, 41);
        state
            .insert_rebate_distribution(rebate)
            .expect("devnet rebate distribution");
        let throttle = AbuseThrottle::new(&state.config, "owner-commitment-beta", 51);
        state
            .insert_abuse_throttle(throttle)
            .expect("devnet abuse throttle");
        let budget = RedactionBudget::new(
            &state.config,
            RedactionScope::OperatorSummary,
            &epoch_id,
            128,
            61,
        );
        state
            .insert_redaction_budget(budget)
            .expect("devnet redaction budget");
        state
            .publish_operator_summary(&epoch_id, 71)
            .expect("devnet operator summary");
        state
    }

    pub fn insert_epoch(&mut self, epoch: BatchNettingEpoch) -> Result<()> {
        ensure!(self.epochs.len() < MAX_EPOCHS, "epoch capacity exceeded");
        ensure!(
            !self.epochs.contains_key(&epoch.epoch_id),
            "epoch {} already exists",
            epoch.epoch_id
        );
        let epoch_id = epoch.epoch_id.clone();
        self.epochs.insert(epoch_id.clone(), epoch);
        self.counters.epochs_opened += 1;
        self.emit("epoch_opened", epoch_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_sponsor_commitment(&mut self, sponsor: SponsorCommitment) -> Result<()> {
        ensure!(
            self.sponsor_commitments.len() < MAX_SPONSORS,
            "sponsor capacity exceeded"
        );
        ensure!(
            sponsor.status.covers(),
            "sponsor {} is not cover-capable",
            sponsor.sponsor_id
        );
        let sponsor_id = sponsor.sponsor_id.clone();
        for lane in &sponsor.lanes {
            self.sponsors_by_lane
                .entry(lane.as_str().to_string())
                .or_default()
                .insert(sponsor_id.clone());
        }
        self.sponsor_commitments.insert(sponsor_id.clone(), sponsor);
        self.counters.sponsor_commitments_registered += 1;
        self.emit("sponsor_commitment_registered", sponsor_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_ledger(
        &mut self,
        epoch_id: &str,
        sponsor_id: &str,
        owner_commitment: impl Into<String>,
        lane: FeeCreditLane,
        nonce: u64,
    ) -> Result<String> {
        ensure!(self.ledgers.len() < MAX_LEDGERS, "ledger capacity exceeded");
        let epoch = self
            .epochs
            .get(epoch_id)
            .ok_or_else(|| format!("epoch {epoch_id} not found"))?;
        ensure!(epoch.status.accepts_ledgers(), "epoch {epoch_id} is closed");
        ensure!(
            epoch.lanes.contains(&lane),
            "lane {} is not enabled",
            lane.as_str()
        );
        let sponsor = self
            .sponsor_commitments
            .get(sponsor_id)
            .ok_or_else(|| format!("sponsor {sponsor_id} not found"))?;
        ensure!(
            sponsor.status.covers(),
            "sponsor {sponsor_id} cannot cover fees"
        );
        ensure!(
            sponsor.lanes.contains(&lane),
            "sponsor {sponsor_id} does not cover lane {}",
            lane.as_str()
        );
        let ledger = FeeCreditLedger::new(
            &self.config,
            epoch_id,
            sponsor_id,
            owner_commitment,
            lane,
            nonce,
        );
        let ledger_id = ledger.ledger_id.clone();
        self.ledger_by_epoch
            .entry(epoch_id.to_string())
            .or_default()
            .insert(ledger_id.clone());
        self.ledgers.insert(ledger_id.clone(), ledger);
        self.counters.ledgers_opened += 1;
        self.emit("fee_credit_ledger_opened", ledger_id.clone());
        self.refresh_roots();
        Ok(ledger_id)
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        ensure!(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "attestation capacity exceeded"
        );
        ensure!(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation {} below PQ security policy",
            attestation.attestation_id
        );
        let attestation_id = attestation.attestation_id.clone();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations_recorded += 1;
        self.emit("pq_attestation_recorded", attestation_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn seal_and_net_epoch(&mut self, epoch_id: &str, attestation_root: &str) -> Result<()> {
        let ledger_ids = self
            .ledger_by_epoch
            .get(epoch_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        let sponsor_count = ledger_ids
            .iter()
            .filter_map(|ledger_id| self.ledgers.get(ledger_id))
            .map(|ledger| ledger.sponsor_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        {
            let epoch = self
                .epochs
                .get_mut(epoch_id)
                .ok_or_else(|| format!("epoch {epoch_id} not found"))?;
            epoch.seal(ledger_ids.len() as u64, sponsor_count)?;
            self.counters.epochs_sealed += 1;
        }
        for ledger_id in &ledger_ids {
            let ledger = self
                .ledgers
                .get_mut(ledger_id)
                .ok_or_else(|| format!("ledger {ledger_id} not found"))?;
            ledger.net(DEVNET_HEIGHT.saturating_add(1))?;
            self.counters.ledgers_netted += 1;
        }
        let voucher_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:NETTED-VOUCHER-ROOT",
            &[HashPart::Str(epoch_id), HashPart::Str(attestation_root)],
            32,
        );
        self.epochs
            .get_mut(epoch_id)
            .expect("epoch exists after seal")
            .mark_netted(voucher_root)?;
        self.emit("epoch_netted", epoch_id.to_string());
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_settlement_voucher(&mut self, voucher: SettlementVoucher) -> Result<()> {
        ensure!(
            self.settlement_vouchers.len() < MAX_VOUCHERS,
            "voucher capacity exceeded"
        );
        ensure!(
            self.epochs
                .get(&voucher.epoch_id)
                .map(|epoch| epoch.status.accepts_vouchers())
                .unwrap_or(false),
            "epoch {} does not accept vouchers",
            voucher.epoch_id
        );
        let voucher_id = voucher.voucher_id.clone();
        let epoch_id = voucher.epoch_id.clone();
        self.vouchers_by_epoch
            .entry(epoch_id)
            .or_default()
            .insert(voucher_id.clone());
        self.settlement_vouchers.insert(voucher_id.clone(), voucher);
        self.counters.settlement_vouchers_issued += 1;
        self.emit("settlement_voucher_issued", voucher_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_voucher(&mut self, voucher_id: &str) -> Result<()> {
        let voucher = self
            .settlement_vouchers
            .get_mut(voucher_id)
            .ok_or_else(|| format!("voucher {voucher_id} not found"))?;
        voucher.settle()?;
        self.counters.settlement_vouchers_settled += 1;
        self.emit("settlement_voucher_settled", voucher_id.to_string());
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_abuse_throttle(&mut self, throttle: AbuseThrottle) -> Result<()> {
        ensure!(
            self.abuse_throttles.len() < MAX_THROTTLES,
            "throttle capacity exceeded"
        );
        let throttle_id = throttle.throttle_id.clone();
        self.abuse_throttles.insert(throttle_id.clone(), throttle);
        self.counters.abuse_throttles_opened += 1;
        self.emit("abuse_throttle_opened", throttle_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_rebate_distribution(&mut self, rebate: RebateDistribution) -> Result<()> {
        ensure!(
            self.rebate_distributions.len() < MAX_REBATES,
            "rebate capacity exceeded"
        );
        ensure!(
            rebate.rebate_bps <= MAX_BPS,
            "rebate {} exceeds MAX_BPS",
            rebate.rebate_id
        );
        let rebate_id = rebate.rebate_id.clone();
        self.rebate_distributions.insert(rebate_id.clone(), rebate);
        self.counters.rebates_distributed += 1;
        self.emit("rebate_distributed", rebate_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure!(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity exceeded"
        );
        ensure!(
            budget.max_units <= self.config.max_redaction_units,
            "redaction budget {} exceeds policy",
            budget.budget_id
        );
        let budget_id = budget.budget_id.clone();
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets_issued += 1;
        self.emit("redaction_budget_issued", budget_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, epoch_id: &str, nonce: u64) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity exceeded"
        );
        ensure!(
            self.epochs.contains_key(epoch_id),
            "epoch {epoch_id} not found"
        );
        let summary = OperatorSafeSummary::new(self, epoch_id, nonce);
        let summary_id = summary.summary_id.clone();
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries_published += 1;
        self.emit("operator_summary_published", summary_id.clone());
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "confidential_fee_credit_scheme": CONFIDENTIAL_FEE_CREDIT_SCHEME,
            "batch_netting_scheme": BATCH_NETTING_SCHEME,
            "sponsor_commitment_scheme": SPONSOR_COMMITMENT_SCHEME,
            "settlement_voucher_scheme": SETTLEMENT_VOUCHER_SCHEME,
            "abuse_throttle_scheme": ABUSE_THROTTLE_SCHEME,
            "rebate_distribution_scheme": REBATE_DISTRIBUTION_SCHEME,
            "redaction_budget_scheme": REDACTION_BUDGET_SCHEME,
            "operator_summary_scheme": OPERATOR_SUMMARY_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "ledgers": self.ledgers.values().map(FeeCreditLedger::public_record).collect::<Vec<_>>(),
            "epochs": self.epochs.values().map(BatchNettingEpoch::public_record).collect::<Vec<_>>(),
            "sponsor_commitments": self.sponsor_commitments.values().map(SponsorCommitment::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqAttestation::public_record).collect::<Vec<_>>(),
            "settlement_vouchers": self.settlement_vouchers.values().map(SettlementVoucher::public_record).collect::<Vec<_>>(),
            "abuse_throttles": self.abuse_throttles.values().map(AbuseThrottle::public_record).collect::<Vec<_>>(),
            "rebate_distributions": self.rebate_distributions.values().map(RebateDistribution::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSafeSummary::public_record).collect::<Vec<_>>(),
            "ledger_by_epoch": self.ledger_by_epoch,
            "sponsors_by_lane": self.sponsors_by_lane,
            "vouchers_by_epoch": self.vouchers_by_epoch,
            "events": self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.ledgers_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:LEDGERS",
            &self
                .ledgers
                .values()
                .map(FeeCreditLedger::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.epochs_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:EPOCHS",
            &self
                .epochs
                .values()
                .map(BatchNettingEpoch::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.sponsor_commitments_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:SPONSORS",
            &self
                .sponsor_commitments
                .values()
                .map(SponsorCommitment::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.pq_attestations_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:ATTESTATIONS",
            &self
                .pq_attestations
                .values()
                .map(PqAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.settlement_vouchers_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:VOUCHERS",
            &self
                .settlement_vouchers
                .values()
                .map(SettlementVoucher::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.abuse_throttles_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:THROTTLES",
            &self
                .abuse_throttles
                .values()
                .map(AbuseThrottle::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.rebate_distributions_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:REBATES",
            &self
                .rebate_distributions
                .values()
                .map(RebateDistribution::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.redaction_budgets_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:REDACTIONS",
            &self
                .redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.operator_summaries_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:SUMMARIES",
            &self
                .operator_summaries
                .values()
                .map(OperatorSafeSummary::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.indexes_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:INDEXES",
            &[
                json!({"ledger_by_epoch": self.ledger_by_epoch}),
                json!({"sponsors_by_lane": self.sponsors_by_lane}),
                json!({"vouchers_by_epoch": self.vouchers_by_epoch}),
            ],
        );
        self.roots.events_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:EVENTS",
            &self
                .events
                .iter()
                .map(RuntimeEvent::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = self.state_root();
    }

    fn emit(&mut self, kind: impl Into<String>, subject_id: impl Into<String>) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let nonce = self.counters.events_emitted.saturating_add(1);
        self.events.push(RuntimeEvent::new(kind, subject_id, nonce));
        self.counters.events_emitted = nonce;
    }
}

impl Roots {
    fn public_record_without_state_root(&self) -> Value {
        json!({
            "ledgers_root": self.ledgers_root,
            "epochs_root": self.epochs_root,
            "sponsor_commitments_root": self.sponsor_commitments_root,
            "pq_attestations_root": self.pq_attestations_root,
            "settlement_vouchers_root": self.settlement_vouchers_root,
            "abuse_throttles_root": self.abuse_throttles_root,
            "rebate_distributions_root": self.rebate_distributions_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "indexes_root": self.indexes_root,
            "events_root": self.events_root,
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:{domain}"),
        &hash_parts,
        32,
    )
}

fn epoch_id(epoch_number: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:EPOCH-ID",
        &[HashPart::U64(epoch_number), HashPart::U64(height)],
        20,
    )
}

fn sponsor_id(sponsor_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:SPONSOR-ID",
        &[HashPart::Str(sponsor_commitment), HashPart::U64(nonce)],
        20,
    )
}

fn ledger_id(epoch_id: &str, owner_commitment: &str, lane: FeeCreditLane, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:LEDGER-ID",
        &[
            HashPart::Str(epoch_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn attestation_id(purpose: AttestationPurpose, subject_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:ATTESTATION-ID",
        &[
            HashPart::Str(&format!("{purpose:?}")),
            HashPart::Str(subject_id),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn voucher_id(epoch_id: &str, sponsor_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:VOUCHER-ID",
        &[
            HashPart::Str(epoch_id),
            HashPart::Str(sponsor_id),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn throttle_id(subject_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:THROTTLE-ID",
        &[HashPart::Str(subject_commitment), HashPart::U64(nonce)],
        20,
    )
}

fn rebate_id(epoch_id: &str, voucher_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:REBATE-ID",
        &[
            HashPart::Str(epoch_id),
            HashPart::Str(voucher_id),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn redaction_budget_id(scope: RedactionScope, subject_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:REDACTION-BUDGET-ID",
        &[
            HashPart::Str(&format!("{scope:?}")),
            HashPart::Str(subject_id),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn operator_summary_id(epoch_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-CREDIT-BATCH-NETTING:OPERATOR-SUMMARY-ID",
        &[HashPart::Str(epoch_id), HashPart::U64(nonce)],
        20,
    )
}
