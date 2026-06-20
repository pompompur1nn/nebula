use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenCovenantRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenCovenantRuntimeResult<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $message:expr $(,)?) => {
        ensure($condition, $message)
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_COVENANT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-token-covenant-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_COVENANT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_552_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_PROOF_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-token-covenant-v1";
pub const CONFIDENTIAL_PROOF_SUITE: &str =
    "RingCT-amount-conservation+membership-nullifier+covenant-transcript-v1";
pub const CONTRACT_HOOK_SUITE: &str = "private-contract-hook-commitment-v1";
pub const SETTLEMENT_SUITE: &str = "recursive-covenant-batch-settlement-v1";
pub const FEE_SPONSOR_SUITE: &str = "roots-only-low-fee-token-covenant-sponsor-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_HOOK_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 7;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_POLICIES: usize = 1_048_576;
pub const DEFAULT_MAX_PROOFS: usize = 16_777_216;
pub const DEFAULT_MAX_NULLIFIERS: usize = 67_108_864;
pub const DEFAULT_MAX_HOOKS: usize = 8_388_608;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 4_194_304;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 8_192;
pub const DEFAULT_MAX_SPONSORS: usize = 4_194_304;
pub const DEFAULT_MAX_REBATES: usize = 16_777_216;
pub const DEFAULT_MAX_SLASHES: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    ConfidentialAsset,
    WrappedMonero,
    StableAsset,
    VaultShare,
    LiquidityReceipt,
    GovernanceNote,
    SyntheticClaim,
    ContractBoundToken,
    CreditNote,
    SettlementCoupon,
}

impl TokenClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAsset => "confidential_asset",
            Self::WrappedMonero => "wrapped_monero",
            Self::StableAsset => "stable_asset",
            Self::VaultShare => "vault_share",
            Self::LiquidityReceipt => "liquidity_receipt",
            Self::GovernanceNote => "governance_note",
            Self::SyntheticClaim => "synthetic_claim",
            Self::ContractBoundToken => "contract_bound_token",
            Self::CreditNote => "credit_note",
            Self::SettlementCoupon => "settlement_coupon",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Active,
    GracePeriod,
    Paused,
    Frozen,
    Superseded,
    Retired,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_activity(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantScope {
    Token,
    Issuer,
    Holder,
    Mint,
    Burn,
    Transfer,
    ContractHook,
    DefiPool,
    BridgeRoute,
    Global,
}

impl CovenantScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Issuer => "issuer",
            Self::Holder => "holder",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Transfer => "transfer",
            Self::ContractHook => "contract_hook",
            Self::DefiPool => "defi_pool",
            Self::BridgeRoute => "bridge_route",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    RegisterPolicy,
    AttachIssuerProof,
    AttachHolderProof,
    Mint,
    Burn,
    Transfer,
    ComplianceNullifier,
    ContractHook,
    SettleBatch,
    SponsorFee,
    RebateFee,
    SlashAttestation,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterPolicy => "register_policy",
            Self::AttachIssuerProof => "attach_issuer_proof",
            Self::AttachHolderProof => "attach_holder_proof",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Transfer => "transfer",
            Self::ComplianceNullifier => "compliance_nullifier",
            Self::ContractHook => "contract_hook",
            Self::SettleBatch => "settle_batch",
            Self::SponsorFee => "sponsor_fee",
            Self::RebateFee => "rebate_fee",
            Self::SlashAttestation => "slash_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSubject {
    Issuer,
    Holder,
    MintAuthority,
    BurnAuthority,
    TransferSender,
    TransferRecipient,
    Sponsor,
    Contract,
    Watchtower,
}

impl ProofSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Holder => "holder",
            Self::MintAuthority => "mint_authority",
            Self::BurnAuthority => "burn_authority",
            Self::TransferSender => "transfer_sender",
            Self::TransferRecipient => "transfer_recipient",
            Self::Sponsor => "sponsor",
            Self::Contract => "contract",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Accepted,
    Quarantined,
    Consumed,
    Expired,
    Revoked,
    Slashed,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Quarantined => "quarantined",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantVerdict {
    Allowed,
    AllowedWithDisclosure,
    SponsorRequired,
    Watch,
    Hold,
    Rejected,
}

impl CovenantVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWithDisclosure => "allowed_with_disclosure",
            Self::SponsorRequired => "sponsor_required",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Rejected => "rejected",
        }
    }

    pub fn permits_settlement(self) -> bool {
        matches!(
            self,
            Self::Allowed | Self::AllowedWithDisclosure | Self::SponsorRequired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    BeforeMint,
    AfterMint,
    BeforeBurn,
    AfterBurn,
    BeforeTransfer,
    AfterTransfer,
    DefiCallback,
    BridgeCallback,
    ComplianceDisclosure,
}

impl HookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeMint => "before_mint",
            Self::AfterMint => "after_mint",
            Self::BeforeBurn => "before_burn",
            Self::AfterBurn => "after_burn",
            Self::BeforeTransfer => "before_transfer",
            Self::AfterTransfer => "after_transfer",
            Self::DefiCallback => "defi_callback",
            Self::BridgeCallback => "bridge_callback",
            Self::ComplianceDisclosure => "compliance_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Preconfirmed,
    Settled,
    Challenged,
    Finalized,
    Reverted,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorshipStatus {
    Reserved,
    Applied,
    Rebated,
    Expired,
    Slashed,
}

impl FeeSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidPqSignature,
    InvalidRangeProof,
    InvalidMembershipProof,
    ReusedNullifier,
    ExpiredProof,
    BadContractHook,
    FeeOvercharge,
    BatchRootMismatch,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::InvalidRangeProof => "invalid_range_proof",
            Self::InvalidMembershipProof => "invalid_membership_proof",
            Self::ReusedNullifier => "reused_nullifier",
            Self::ExpiredProof => "expired_proof",
            Self::BadContractHook => "bad_contract_hook",
            Self::FeeOvercharge => "fee_overcharge",
            Self::BatchRootMismatch => "batch_root_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub policy_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub hook_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slash_bps: u64,
    pub max_policies: usize,
    pub max_proofs: usize,
    pub max_nullifiers: usize,
    pub max_hooks: usize,
    pub max_settlements: usize,
    pub max_batch_items: usize,
    pub max_sponsors: usize,
    pub max_rebates: usize,
    pub max_slashes: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            l2_network: "nebula-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            hook_ttl_blocks: DEFAULT_HOOK_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_policies: DEFAULT_MAX_POLICIES,
            max_proofs: DEFAULT_MAX_PROOFS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            max_hooks: DEFAULT_MAX_HOOKS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_sponsors: DEFAULT_MAX_SPONSORS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_slashes: DEFAULT_MAX_SLASHES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("slash_bps", self.slash_bps)?;
        ensure_nonzero("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_nonzero("batch_privacy_set_size", self.batch_privacy_set_size)?;
        ensure!(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set must be at least the minimum privacy set"
        )?;
        ensure!(
            self.min_pq_security_bits >= 192,
            "min_pq_security_bits below post-quantum floor"
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policy_count: u64,
    pub proof_count: u64,
    pub nullifier_count: u64,
    pub hook_count: u64,
    pub settlement_count: u64,
    pub sponsor_count: u64,
    pub rebate_count: u64,
    pub slash_count: u64,
    pub event_count: u64,
    pub total_minted_commitments: u64,
    pub total_burned_commitments: u64,
    pub total_transfer_commitments: u64,
    pub total_sponsored_fee_commitments: u64,
    pub total_rebate_commitments: u64,
    pub total_slashed_stake_commitments: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub policy_root: String,
    pub proof_root: String,
    pub issuer_proof_root: String,
    pub holder_proof_root: String,
    pub nullifier_root: String,
    pub hook_root: String,
    pub settlement_root: String,
    pub sponsor_root: String,
    pub rebate_root: String,
    pub slash_root: String,
    pub event_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub policies: BTreeMap<String, CovenantPolicy>,
    pub proofs: BTreeMap<String, PqCovenantProof>,
    pub issuer_proofs: BTreeMap<String, BTreeSet<String>>,
    pub holder_proofs: BTreeMap<String, BTreeSet<String>>,
    pub nullifiers: BTreeMap<String, ComplianceNullifier>,
    pub hooks: BTreeMap<String, ContractHookCommitment>,
    pub settlements: BTreeMap<String, BatchSettlement>,
    pub sponsors: BTreeMap<String, FeeSponsorship>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashes: BTreeMap<String, SlashRecord>,
    pub events: Vec<RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            counters: Counters::default(),
            policies: BTreeMap::new(),
            proofs: BTreeMap::new(),
            issuer_proofs: BTreeMap::new(),
            holder_proofs: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            hooks: BTreeMap::new(),
            settlements: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashes: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn with_config(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            ..Self::devnet()
        })
    }

    pub fn roots(&self) -> Roots {
        Roots {
            policy_root: record_root("PQL2-COVENANT-POLICY-ROOT", self.policies.values()),
            proof_root: record_root("PQL2-COVENANT-PROOF-ROOT", self.proofs.values()),
            issuer_proof_root: index_root("PQL2-COVENANT-ISSUER-PROOF-ROOT", &self.issuer_proofs),
            holder_proof_root: index_root("PQL2-COVENANT-HOLDER-PROOF-ROOT", &self.holder_proofs),
            nullifier_root: record_root("PQL2-COVENANT-NULLIFIER-ROOT", self.nullifiers.values()),
            hook_root: record_root("PQL2-COVENANT-HOOK-ROOT", self.hooks.values()),
            settlement_root: record_root(
                "PQL2-COVENANT-SETTLEMENT-ROOT",
                self.settlements.values(),
            ),
            sponsor_root: record_root("PQL2-COVENANT-SPONSOR-ROOT", self.sponsors.values()),
            rebate_root: record_root("PQL2-COVENANT-REBATE-ROOT", self.rebates.values()),
            slash_root: record_root("PQL2-COVENANT-SLASH-ROOT", self.slashes.values()),
            event_root: record_root("PQL2-COVENANT-EVENT-ROOT", self.events.iter()),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "config": self.config,
            "counters": self.counters,
            "roots": roots,
        });
        digest_json("PQL2-COVENANT-STATE-ROOT", &record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "hash_suite": HASH_SUITE,
            "pq_proof_suite": PQ_PROOF_SUITE,
            "confidential_proof_suite": CONFIDENTIAL_PROOF_SUITE,
            "contract_hook_suite": CONTRACT_HOOK_SUITE,
            "settlement_suite": SETTLEMENT_SUITE,
            "fee_sponsor_suite": FEE_SPONSOR_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots(),
            "state_root": self.state_root(),
        })
    }

    pub fn register_policy(&mut self, request: RegisterPolicyRequest) -> Result<CovenantPolicy> {
        self.config.validate()?;
        ensure_capacity("policies", self.policies.len(), self.config.max_policies)?;
        ensure_nonempty("token_id", &request.token_id)?;
        ensure_nonempty("issuer_commitment", &request.issuer_commitment)?;
        ensure_nonzero("privacy_set_size", request.privacy_set_size)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below covenant floor"
        )?;
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits below runtime floor"
        )?;
        ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        ensure!(
            request.max_user_fee_bps <= self.config.max_user_fee_bps,
            "user fee exceeds runtime cap"
        )?;
        let policy_id = policy_id(&request);
        ensure_absent(&self.policies, "policy", &policy_id)?;
        let covenant_root = covenant_root(&request.required_scopes, &request.rule_commitments);
        let metadata_commitment =
            optional_json_commitment("PQL2-COVENANT-POLICY-METADATA", request.metadata.as_ref());
        let policy = CovenantPolicy {
            policy_id: policy_id.clone(),
            token_id: request.token_id,
            token_class: request.token_class,
            issuer_commitment: request.issuer_commitment,
            status: PolicyStatus::Active,
            required_scopes: request.required_scopes,
            rule_commitments: request.rule_commitments,
            covenant_root,
            issuer_pq_root: request.issuer_pq_root,
            holder_pq_root: request.holder_pq_root,
            mint_limit_commitment: request.mint_limit_commitment,
            burn_limit_commitment: request.burn_limit_commitment,
            transfer_limit_commitment: request.transfer_limit_commitment,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_user_fee_bps: request.max_user_fee_bps,
            valid_from_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.policy_ttl_blocks),
            metadata_commitment,
            created_at_height: self.height,
        };
        self.policies.insert(policy_id.clone(), policy.clone());
        self.counters.policy_count += 1;
        self.push_event(OperationKind::RegisterPolicy, policy_id, policy.record());
        Ok(policy)
    }

    pub fn attach_pq_issuer_proof(
        &mut self,
        request: AttachPqProofRequest,
    ) -> Result<PqCovenantProof> {
        self.attach_pq_proof(request, ProofSubject::Issuer)
    }

    pub fn attach_pq_holder_proof(
        &mut self,
        request: AttachPqProofRequest,
    ) -> Result<PqCovenantProof> {
        self.attach_pq_proof(request, ProofSubject::Holder)
    }

    pub fn check_mint_covenant(&mut self, request: MintCovenantRequest) -> Result<CovenantCheck> {
        let policy = self.active_policy(&request.policy_id)?;
        ensure!(
            policy.required_scopes.contains(&CovenantScope::Mint),
            "policy does not authorize mint covenant"
        )?;
        ensure_nonempty("recipient_commitment", &request.recipient_commitment)?;
        ensure_nonempty("amount_commitment", &request.amount_commitment)?;
        self.require_proof(&request.issuer_proof_id, ProofSubject::Issuer, policy)?;
        self.require_fresh_nullifier(&request.mint_nullifier)?;
        let verdict = self.verdict_for_fee(request.max_fee_bps, false)?;
        let check_id = operation_id(
            "PQL2-COVENANT-MINT-CHECK-ID",
            &json!({
                "policy_id": request.policy_id,
                "recipient_commitment": request.recipient_commitment,
                "amount_commitment": request.amount_commitment,
                "mint_nullifier": request.mint_nullifier,
                "height": self.height,
            }),
        );
        let check = CovenantCheck {
            check_id: check_id.clone(),
            policy_id: policy.policy_id.clone(),
            operation: OperationKind::Mint,
            verdict,
            proof_ids: vec![request.issuer_proof_id],
            nullifier_ids: vec![request.mint_nullifier.clone()],
            hook_ids: request.hook_ids,
            fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            transcript_root: request.transcript_root,
            created_at_height: self.height,
        };
        self.insert_nullifier(
            request.mint_nullifier,
            policy.policy_id.clone(),
            OperationKind::Mint,
            check_id.clone(),
        )?;
        self.counters.total_minted_commitments += 1;
        self.push_event(OperationKind::Mint, check_id, check.record());
        Ok(check)
    }

    pub fn check_burn_covenant(&mut self, request: BurnCovenantRequest) -> Result<CovenantCheck> {
        let policy = self.active_policy(&request.policy_id)?;
        ensure!(
            policy.required_scopes.contains(&CovenantScope::Burn),
            "policy does not authorize burn covenant"
        )?;
        ensure_nonempty("holder_commitment", &request.holder_commitment)?;
        ensure_nonempty("amount_commitment", &request.amount_commitment)?;
        self.require_proof(&request.holder_proof_id, ProofSubject::Holder, policy)?;
        self.require_fresh_nullifier(&request.burn_nullifier)?;
        let verdict = self.verdict_for_fee(request.max_fee_bps, false)?;
        let check_id = operation_id(
            "PQL2-COVENANT-BURN-CHECK-ID",
            &json!({
                "policy_id": request.policy_id,
                "holder_commitment": request.holder_commitment,
                "amount_commitment": request.amount_commitment,
                "burn_nullifier": request.burn_nullifier,
                "height": self.height,
            }),
        );
        let check = CovenantCheck {
            check_id: check_id.clone(),
            policy_id: policy.policy_id.clone(),
            operation: OperationKind::Burn,
            verdict,
            proof_ids: vec![request.holder_proof_id],
            nullifier_ids: vec![request.burn_nullifier.clone()],
            hook_ids: request.hook_ids,
            fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            transcript_root: request.transcript_root,
            created_at_height: self.height,
        };
        self.insert_nullifier(
            request.burn_nullifier,
            policy.policy_id.clone(),
            OperationKind::Burn,
            check_id.clone(),
        )?;
        self.counters.total_burned_commitments += 1;
        self.push_event(OperationKind::Burn, check_id, check.record());
        Ok(check)
    }

    pub fn check_transfer_covenant(
        &mut self,
        request: TransferCovenantRequest,
    ) -> Result<CovenantCheck> {
        let policy = self.active_policy(&request.policy_id)?;
        ensure!(
            policy.required_scopes.contains(&CovenantScope::Transfer),
            "policy does not authorize transfer covenant"
        )?;
        ensure_nonempty("sender_commitment", &request.sender_commitment)?;
        ensure_nonempty("recipient_commitment", &request.recipient_commitment)?;
        ensure_nonempty("amount_commitment", &request.amount_commitment)?;
        self.require_proof(&request.sender_proof_id, ProofSubject::Holder, policy)?;
        if let Some(recipient_proof_id) = &request.recipient_proof_id {
            self.require_proof(recipient_proof_id, ProofSubject::Holder, policy)?;
        }
        self.require_fresh_nullifier(&request.spend_nullifier)?;
        let verdict = self.verdict_for_fee(request.max_fee_bps, request.sponsor_id.is_some())?;
        let check_id = operation_id(
            "PQL2-COVENANT-TRANSFER-CHECK-ID",
            &json!({
                "policy_id": request.policy_id,
                "sender_commitment": request.sender_commitment,
                "recipient_commitment": request.recipient_commitment,
                "amount_commitment": request.amount_commitment,
                "spend_nullifier": request.spend_nullifier,
                "height": self.height,
            }),
        );
        if let Some(sponsor_id) = &request.sponsor_id {
            self.apply_fee_sponsorship(sponsor_id, &check_id)?;
        }
        let mut proof_ids = vec![request.sender_proof_id];
        if let Some(recipient_proof_id) = request.recipient_proof_id {
            proof_ids.push(recipient_proof_id);
        }
        let check = CovenantCheck {
            check_id: check_id.clone(),
            policy_id: policy.policy_id.clone(),
            operation: OperationKind::Transfer,
            verdict,
            proof_ids,
            nullifier_ids: vec![request.spend_nullifier.clone()],
            hook_ids: request.hook_ids,
            fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            transcript_root: request.transcript_root,
            created_at_height: self.height,
        };
        self.insert_nullifier(
            request.spend_nullifier,
            policy.policy_id.clone(),
            OperationKind::Transfer,
            check_id.clone(),
        )?;
        self.counters.total_transfer_commitments += 1;
        self.push_event(OperationKind::Transfer, check_id, check.record());
        Ok(check)
    }

    pub fn register_private_compliance_nullifier(
        &mut self,
        request: ComplianceNullifierRequest,
    ) -> Result<ComplianceNullifier> {
        self.active_policy(&request.policy_id)?;
        self.require_fresh_nullifier(&request.nullifier)?;
        let binding = operation_id(
            "PQL2-COVENANT-COMPLIANCE-BINDING-ID",
            &json!({
                "policy_id": request.policy_id,
                "operation": request.operation.as_str(),
                "witness_root": request.witness_root,
                "disclosure_commitment": request.disclosure_commitment,
            }),
        );
        let record = ComplianceNullifier {
            nullifier: request.nullifier.clone(),
            policy_id: request.policy_id,
            operation: request.operation,
            bound_check_id: binding.clone(),
            witness_root: request.witness_root,
            disclosure_commitment: request.disclosure_commitment,
            created_at_height: self.height,
        };
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        self.nullifiers
            .insert(request.nullifier.clone(), record.clone());
        self.counters.nullifier_count += 1;
        self.push_event(
            OperationKind::ComplianceNullifier,
            request.nullifier,
            record.record(),
        );
        Ok(record)
    }

    pub fn commit_contract_hook(
        &mut self,
        request: ContractHookRequest,
    ) -> Result<ContractHookCommitment> {
        let policy = self.active_policy(&request.policy_id)?;
        ensure!(
            policy
                .required_scopes
                .contains(&CovenantScope::ContractHook),
            "policy does not authorize contract hook covenant"
        )?;
        ensure_capacity("hooks", self.hooks.len(), self.config.max_hooks)?;
        ensure_nonempty("contract_commitment", &request.contract_commitment)?;
        ensure_nonempty(
            "method_selector_commitment",
            &request.method_selector_commitment,
        )?;
        let hook_id = hook_id(&request, self.height);
        ensure_absent(&self.hooks, "hook", &hook_id)?;
        let hook = ContractHookCommitment {
            hook_id: hook_id.clone(),
            policy_id: request.policy_id,
            hook_kind: request.hook_kind,
            contract_commitment: request.contract_commitment,
            method_selector_commitment: request.method_selector_commitment,
            calldata_root: request.calldata_root,
            pre_state_root: request.pre_state_root,
            post_state_root: request.post_state_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_budget_commitment: request.privacy_budget_commitment,
            expires_at_height: self.height.saturating_add(self.config.hook_ttl_blocks),
            created_at_height: self.height,
        };
        self.hooks.insert(hook_id.clone(), hook.clone());
        self.counters.hook_count += 1;
        self.push_event(OperationKind::ContractHook, hook_id, hook.record());
        Ok(hook)
    }

    pub fn settle_covenant_batch(
        &mut self,
        request: BatchSettlementRequest,
    ) -> Result<BatchSettlement> {
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        ensure!(
            !request.checks.is_empty(),
            "settlement batch must contain at least one check"
        )?;
        ensure!(
            request.checks.len() <= self.config.max_batch_items,
            "settlement batch exceeds max items"
        )?;
        ensure_nonempty("operator_commitment", &request.operator_commitment)?;
        ensure_nonempty("recursive_proof_root", &request.recursive_proof_root)?;
        let rejected = request
            .checks
            .iter()
            .filter(|check| !check.verdict.permits_settlement())
            .count();
        ensure!(rejected == 0, "settlement batch contains rejected checks")?;
        let batch_root = check_root(&request.checks);
        ensure_eq("batch_root", &batch_root, &request.claimed_batch_root)?;
        let settlement_id = settlement_id(&request, self.height);
        ensure_absent(&self.settlements, "settlement", &settlement_id)?;
        let settlement = BatchSettlement {
            settlement_id: settlement_id.clone(),
            status: SettlementStatus::Settled,
            operator_commitment: request.operator_commitment,
            batch_root,
            claimed_batch_root: request.claimed_batch_root,
            recursive_proof_root: request.recursive_proof_root,
            da_commitment: request.da_commitment,
            fee_commitment_root: request.fee_commitment_root,
            settlement_height: self.height,
            finalizes_at_height: self
                .height
                .saturating_add(self.config.settlement_window_blocks),
            item_count: request.checks.len() as u64,
            privacy_set_size: request.privacy_set_size,
        };
        self.settlements
            .insert(settlement_id.clone(), settlement.clone());
        self.counters.settlement_count += 1;
        self.push_event(
            OperationKind::SettleBatch,
            settlement_id,
            settlement.record(),
        );
        Ok(settlement)
    }

    pub fn reserve_fee_sponsorship(
        &mut self,
        request: FeeSponsorshipRequest,
    ) -> Result<FeeSponsorship> {
        ensure_capacity("sponsors", self.sponsors.len(), self.config.max_sponsors)?;
        ensure_bps("sponsor_fee_bps", request.sponsor_fee_bps)?;
        ensure!(
            request.sponsor_fee_bps <= self.config.max_sponsor_fee_bps,
            "sponsor fee exceeds runtime cap"
        )?;
        ensure_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        ensure_nonempty("budget_commitment", &request.budget_commitment)?;
        let sponsor_id = sponsor_id(&request, self.height);
        ensure_absent(&self.sponsors, "sponsor", &sponsor_id)?;
        let sponsor = FeeSponsorship {
            sponsor_id: sponsor_id.clone(),
            policy_id: request.policy_id,
            sponsor_commitment: request.sponsor_commitment,
            budget_commitment: request.budget_commitment,
            fee_asset_id: request.fee_asset_id,
            sponsor_fee_bps: request.sponsor_fee_bps,
            status: FeeSponsorshipStatus::Reserved,
            applies_to_root: request.applies_to_root,
            pq_authorization_root: request.pq_authorization_root,
            reserved_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.sponsor_ttl_blocks),
            applied_check_id: None,
        };
        self.sponsors.insert(sponsor_id.clone(), sponsor.clone());
        self.counters.sponsor_count += 1;
        self.counters.total_sponsored_fee_commitments += 1;
        self.push_event(OperationKind::SponsorFee, sponsor_id, sponsor.record());
        Ok(sponsor)
    }

    pub fn issue_fee_rebate(&mut self, request: FeeRebateRequest) -> Result<FeeRebate> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        ensure!(
            request.rebate_bps <= self.config.target_rebate_bps,
            "rebate exceeds runtime target"
        )?;
        ensure_nonempty("recipient_commitment", &request.recipient_commitment)?;
        ensure_nonempty("rebate_commitment", &request.rebate_commitment)?;
        let settlement = self
            .settlements
            .get(&request.settlement_id)
            .ok_or_else(|| format!("unknown settlement {}", request.settlement_id))?;
        ensure!(
            matches!(
                settlement.status,
                SettlementStatus::Settled | SettlementStatus::Finalized
            ),
            "rebate requires settled batch"
        )?;
        let rebate_id = rebate_id(&request, self.height);
        ensure_absent(&self.rebates, "rebate", &rebate_id)?;
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            settlement_id: request.settlement_id,
            sponsor_id: request.sponsor_id,
            recipient_commitment: request.recipient_commitment,
            rebate_commitment: request.rebate_commitment,
            rebate_bps: request.rebate_bps,
            proof_root: request.proof_root,
            issued_at_height: self.height,
        };
        self.rebates.insert(rebate_id.clone(), rebate.clone());
        self.counters.rebate_count += 1;
        self.counters.total_rebate_commitments += 1;
        self.push_event(OperationKind::RebateFee, rebate_id, rebate.record());
        Ok(rebate)
    }

    pub fn slash_invalid_attestation(
        &mut self,
        request: SlashAttestationRequest,
    ) -> Result<SlashRecord> {
        ensure_capacity("slashes", self.slashes.len(), self.config.max_slashes)?;
        ensure_nonempty("evidence_root", &request.evidence_root)?;
        ensure_nonempty("challenger_commitment", &request.challenger_commitment)?;
        let proof = self
            .proofs
            .get_mut(&request.proof_id)
            .ok_or_else(|| format!("unknown proof {}", request.proof_id))?;
        ensure!(
            !matches!(proof.status, ProofStatus::Slashed),
            "proof already slashed"
        )?;
        proof.status = ProofStatus::Slashed;
        let slash_id = slash_id(&request, self.height);
        ensure_absent(&self.slashes, "slash", &slash_id)?;
        let slash = SlashRecord {
            slash_id: slash_id.clone(),
            proof_id: request.proof_id,
            reason: request.reason,
            evidence_root: request.evidence_root,
            challenger_commitment: request.challenger_commitment,
            slashed_stake_commitment: request.slashed_stake_commitment,
            slash_bps: self.config.slash_bps,
            created_at_height: self.height,
        };
        self.slashes.insert(slash_id.clone(), slash.clone());
        self.counters.slash_count += 1;
        self.counters.total_slashed_stake_commitments += 1;
        self.push_event(OperationKind::SlashAttestation, slash_id, slash.record());
        Ok(slash)
    }

    pub fn quote_covenant_fee(&self, request: CovenantFeeQuoteRequest) -> Result<CovenantFeeQuote> {
        let policy = self.active_policy(&request.policy_id)?;
        ensure_bps("requested_fee_bps", request.requested_fee_bps)?;
        ensure_nonzero("privacy_set_size", request.privacy_set_size)?;
        let privacy_multiplier_bps =
            privacy_multiplier_bps(request.privacy_set_size, self.config.min_privacy_set_size);
        let base_fee_bps = request
            .requested_fee_bps
            .saturating_mul(privacy_multiplier_bps)
            / MAX_BPS;
        let capped_user_fee_bps = base_fee_bps.min(policy.max_user_fee_bps);
        let sponsor_discount_bps = if request.sponsor_available {
            self.config.target_rebate_bps
        } else {
            0
        };
        let effective_fee_bps = capped_user_fee_bps.saturating_sub(sponsor_discount_bps);
        let verdict = self.verdict_for_fee(effective_fee_bps, request.sponsor_available)?;
        let quote_id = digest_json(
            "PQL2-COVENANT-FEE-QUOTE-ID",
            &json!({
                "policy_id": request.policy_id,
                "operation": request.operation.as_str(),
                "requested_fee_bps": request.requested_fee_bps,
                "privacy_set_size": request.privacy_set_size,
                "sponsor_available": request.sponsor_available,
                "height": self.height,
            }),
        );
        Ok(CovenantFeeQuote {
            quote_id,
            policy_id: policy.policy_id.clone(),
            operation: request.operation,
            requested_fee_bps: request.requested_fee_bps,
            capped_user_fee_bps,
            sponsor_discount_bps,
            effective_fee_bps,
            privacy_multiplier_bps,
            verdict,
            expires_at_height: self.height.saturating_add(self.config.sponsor_ttl_blocks),
        })
    }

    pub fn inspect_policy(&self, policy_id: &str) -> Result<PolicyInspection> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| format!("unknown policy {policy_id}"))?;
        let issuer_proof_count = self
            .issuer_proofs
            .get(policy_id)
            .map(BTreeSet::len)
            .unwrap_or_default() as u64;
        let holder_proof_count = self
            .holder_proofs
            .get(policy_id)
            .map(BTreeSet::len)
            .unwrap_or_default() as u64;
        let nullifier_count = self
            .nullifiers
            .values()
            .filter(|nullifier| nullifier.policy_id == policy_id)
            .count() as u64;
        let hook_count = self
            .hooks
            .values()
            .filter(|hook| hook.policy_id == policy_id)
            .count() as u64;
        let sponsor_count = self
            .sponsors
            .values()
            .filter(|sponsor| sponsor.policy_id == policy_id)
            .count() as u64;
        Ok(PolicyInspection {
            policy_id: policy_id.to_string(),
            token_id: policy.token_id.clone(),
            status: policy.status,
            covenant_root: policy.covenant_root.clone(),
            issuer_proof_count,
            holder_proof_count,
            nullifier_count,
            hook_count,
            sponsor_count,
            expired: self.height > policy.expires_at_height,
            accepts_activity: policy.status.accepts_activity()
                && self.height <= policy.expires_at_height,
            state_root: self.state_root(),
        })
    }

    pub fn set_policy_status(
        &mut self,
        policy_id: &str,
        status: PolicyStatus,
        authority_proof_id: &str,
    ) -> Result<CovenantPolicy> {
        {
            let policy = self
                .policies
                .get(policy_id)
                .ok_or_else(|| format!("unknown policy {policy_id}"))?;
            self.require_proof(authority_proof_id, ProofSubject::Issuer, policy)?;
        }
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| format!("unknown policy {policy_id}"))?;
        policy.status = status;
        let updated = policy.clone();
        self.push_event(
            OperationKind::RegisterPolicy,
            policy_id.to_string(),
            updated.record(),
        );
        Ok(updated)
    }

    pub fn finalize_settlement(&mut self, settlement_id: &str) -> Result<BatchSettlement> {
        let settlement = self
            .settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        ensure!(
            self.height >= settlement.finalizes_at_height,
            "settlement finality window is still open"
        )?;
        ensure!(
            matches!(
                settlement.status,
                SettlementStatus::Settled | SettlementStatus::Preconfirmed
            ),
            "settlement cannot be finalized from current status"
        )?;
        settlement.status = SettlementStatus::Finalized;
        let finalized = settlement.clone();
        self.push_event(
            OperationKind::SettleBatch,
            settlement_id.to_string(),
            finalized.record(),
        );
        Ok(finalized)
    }

    pub fn challenge_settlement(
        &mut self,
        settlement_id: &str,
        evidence_root: &str,
        challenger_commitment: &str,
    ) -> Result<BatchSettlement> {
        ensure_nonempty("evidence_root", evidence_root)?;
        ensure_nonempty("challenger_commitment", challenger_commitment)?;
        let settlement = self
            .settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        ensure!(
            self.height <= settlement.finalizes_at_height,
            "settlement challenge window has closed"
        )?;
        ensure!(
            matches!(
                settlement.status,
                SettlementStatus::Settled | SettlementStatus::Preconfirmed
            ),
            "settlement cannot be challenged from current status"
        )?;
        settlement.status = SettlementStatus::Challenged;
        let challenged = settlement.clone();
        self.push_event(
            OperationKind::SettleBatch,
            settlement_id.to_string(),
            json!({
                "settlement": challenged.record(),
                "evidence_root": evidence_root,
                "challenger_commitment": challenger_commitment,
            }),
        );
        Ok(challenged)
    }

    pub fn expire_stale_records(&mut self, now_height: u64) -> ExpiryReport {
        self.height = self.height.max(now_height);
        let mut report = ExpiryReport::default();
        for policy in self.policies.values_mut() {
            if policy.status.accepts_activity() && self.height > policy.expires_at_height {
                policy.status = PolicyStatus::Retired;
                report.expired_policies += 1;
            }
        }
        for proof in self.proofs.values_mut() {
            if proof.status.usable() && self.height > proof.expires_at_height {
                proof.status = ProofStatus::Expired;
                report.expired_proofs += 1;
            }
        }
        for hook in self.hooks.values() {
            if self.height > hook.expires_at_height {
                report.expired_hooks += 1;
            }
        }
        for sponsor in self.sponsors.values_mut() {
            if sponsor.status == FeeSponsorshipStatus::Reserved
                && self.height > sponsor.expires_at_height
            {
                sponsor.status = FeeSponsorshipStatus::Expired;
                report.expired_sponsorships += 1;
            }
        }
        report.state_root = self.state_root();
        report
    }

    pub fn policy_ids_for_token(&self, token_id: &str) -> Vec<String> {
        self.policies
            .values()
            .filter(|policy| policy.token_id == token_id)
            .map(|policy| policy.policy_id.clone())
            .collect()
    }

    pub fn proofs_for_policy(&self, policy_id: &str, subject: ProofSubject) -> Vec<String> {
        match subject {
            ProofSubject::Issuer => self
                .issuer_proofs
                .get(policy_id)
                .map(|values| values.iter().cloned().collect())
                .unwrap_or_default(),
            ProofSubject::Holder => self
                .holder_proofs
                .get(policy_id)
                .map(|values| values.iter().cloned().collect())
                .unwrap_or_default(),
            _ => self
                .proofs
                .values()
                .filter(|proof| proof.policy_id == policy_id && proof.subject == subject)
                .map(|proof| proof.proof_id.clone())
                .collect(),
        }
    }

    pub fn open_sponsorships_for_policy(&self, policy_id: &str) -> Vec<String> {
        self.sponsors
            .values()
            .filter(|sponsor| {
                sponsor.policy_id == policy_id
                    && sponsor.status == FeeSponsorshipStatus::Reserved
                    && self.height <= sponsor.expires_at_height
            })
            .map(|sponsor| sponsor.sponsor_id.clone())
            .collect()
    }

    pub fn covenant_activity_summary(&self) -> CovenantActivitySummary {
        let active_policies = self
            .policies
            .values()
            .filter(|policy| {
                policy.status.accepts_activity() && self.height <= policy.expires_at_height
            })
            .count() as u64;
        let usable_proofs = self
            .proofs
            .values()
            .filter(|proof| proof.status.usable() && self.height <= proof.expires_at_height)
            .count() as u64;
        let open_sponsorships = self
            .sponsors
            .values()
            .filter(|sponsor| {
                sponsor.status == FeeSponsorshipStatus::Reserved
                    && self.height <= sponsor.expires_at_height
            })
            .count() as u64;
        let unsettled_batches = self
            .settlements
            .values()
            .filter(|settlement| {
                matches!(
                    settlement.status,
                    SettlementStatus::Open
                        | SettlementStatus::Preconfirmed
                        | SettlementStatus::Settled
                        | SettlementStatus::Challenged
                )
            })
            .count() as u64;
        CovenantActivitySummary {
            height: self.height,
            active_policies,
            usable_proofs,
            consumed_nullifiers: self.nullifiers.len() as u64,
            live_hooks: self
                .hooks
                .values()
                .filter(|hook| self.height <= hook.expires_at_height)
                .count() as u64,
            open_sponsorships,
            unsettled_batches,
            slash_count: self.slashes.len() as u64,
            state_root: self.state_root(),
        }
    }

    fn attach_pq_proof(
        &mut self,
        request: AttachPqProofRequest,
        expected_subject: ProofSubject,
    ) -> Result<PqCovenantProof> {
        let policy = self.active_policy(&request.policy_id)?;
        ensure_capacity("proofs", self.proofs.len(), self.config.max_proofs)?;
        ensure!(
            request.subject == expected_subject,
            "proof subject does not match attachment method"
        )?;
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "proof pq security below runtime floor"
        )?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "proof privacy set below runtime floor"
        )?;
        ensure_nonempty("subject_commitment", &request.subject_commitment)?;
        ensure_nonempty(
            "pq_public_key_commitment",
            &request.pq_public_key_commitment,
        )?;
        ensure_nonempty("proof_root", &request.proof_root)?;
        let proof_id = proof_id(&request);
        ensure_absent(&self.proofs, "proof", &proof_id)?;
        let proof = PqCovenantProof {
            proof_id: proof_id.clone(),
            policy_id: policy.policy_id.clone(),
            subject: request.subject,
            subject_commitment: request.subject_commitment,
            pq_public_key_commitment: request.pq_public_key_commitment,
            proof_root: request.proof_root,
            signature_root: request.signature_root,
            membership_root: request.membership_root,
            nullifier_domain: request.nullifier_domain,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: ProofStatus::Accepted,
            issued_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.proof_ttl_blocks),
        };
        self.proofs.insert(proof_id.clone(), proof.clone());
        match expected_subject {
            ProofSubject::Issuer => {
                self.issuer_proofs
                    .entry(policy.policy_id.clone())
                    .or_default()
                    .insert(proof_id.clone());
                self.push_event(OperationKind::AttachIssuerProof, proof_id, proof.record());
            }
            ProofSubject::Holder => {
                self.holder_proofs
                    .entry(policy.policy_id.clone())
                    .or_default()
                    .insert(proof_id.clone());
                self.push_event(OperationKind::AttachHolderProof, proof_id, proof.record());
            }
            _ => return Err("unsupported attachment subject".to_string()),
        }
        self.counters.proof_count += 1;
        Ok(proof)
    }

    fn active_policy(&self, policy_id: &str) -> Result<&CovenantPolicy> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| format!("unknown policy {policy_id}"))?;
        ensure!(
            policy.status.accepts_activity(),
            "policy is not accepting covenant activity"
        )?;
        ensure!(
            self.height <= policy.expires_at_height,
            "policy has expired at current height"
        )?;
        Ok(policy)
    }

    fn require_proof(
        &self,
        proof_id: &str,
        subject: ProofSubject,
        policy: &CovenantPolicy,
    ) -> Result<()> {
        let proof = self
            .proofs
            .get(proof_id)
            .ok_or_else(|| format!("unknown proof {proof_id}"))?;
        ensure_eq("proof policy", &proof.policy_id, &policy.policy_id)?;
        ensure!(
            proof.subject == subject,
            "proof subject does not match covenant requirement"
        )?;
        ensure!(proof.status.usable(), "proof status is not usable")?;
        ensure!(
            self.height <= proof.expires_at_height,
            "proof expired at current height"
        )?;
        Ok(())
    }

    fn require_fresh_nullifier(&self, nullifier: &str) -> Result<()> {
        ensure_nonempty("nullifier", nullifier)?;
        ensure!(
            !self.nullifiers.contains_key(nullifier),
            "nullifier already consumed"
        )
    }

    fn insert_nullifier(
        &mut self,
        nullifier: String,
        policy_id: String,
        operation: OperationKind,
        bound_check_id: String,
    ) -> Result<()> {
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        let record = ComplianceNullifier {
            nullifier: nullifier.clone(),
            policy_id,
            operation,
            bound_check_id,
            witness_root: digest_text("PQL2-COVENANT-IMPLICIT-WITNESS", &nullifier),
            disclosure_commitment: None,
            created_at_height: self.height,
        };
        self.nullifiers.insert(nullifier, record);
        self.counters.nullifier_count += 1;
        Ok(())
    }

    fn verdict_for_fee(&self, fee_bps: u64, sponsored: bool) -> Result<CovenantVerdict> {
        ensure_bps("fee_bps", fee_bps)?;
        if fee_bps <= self.config.max_sponsor_fee_bps && sponsored {
            Ok(CovenantVerdict::SponsorRequired)
        } else if fee_bps <= self.config.max_user_fee_bps {
            Ok(CovenantVerdict::Allowed)
        } else {
            Ok(CovenantVerdict::Hold)
        }
    }

    fn apply_fee_sponsorship(&mut self, sponsor_id: &str, check_id: &str) -> Result<()> {
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| format!("unknown sponsor {sponsor_id}"))?;
        ensure!(
            sponsor.status == FeeSponsorshipStatus::Reserved,
            "sponsorship is not reserved"
        )?;
        ensure!(
            self.height <= sponsor.expires_at_height,
            "sponsorship expired at current height"
        )?;
        sponsor.status = FeeSponsorshipStatus::Applied;
        sponsor.applied_check_id = Some(check_id.to_string());
        Ok(())
    }

    fn push_event(&mut self, operation: OperationKind, object_id: String, payload: Value) {
        let event = RuntimeEvent {
            event_id: event_id(
                operation,
                &object_id,
                self.height,
                self.counters.event_count,
            ),
            operation,
            object_id,
            payload_commitment: digest_json("PQL2-COVENANT-EVENT-PAYLOAD", &payload),
            state_root_after: digest_json(
                "PQL2-COVENANT-EVENT-SNAPSHOT",
                &json!({
                    "height": self.height,
                    "counters": self.counters,
                }),
            ),
            height: self.height,
            ordinal: self.counters.event_count,
        };
        self.counters.event_count += 1;
        self.events.push(event);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantPolicy {
    pub policy_id: String,
    pub token_id: String,
    pub token_class: TokenClass,
    pub issuer_commitment: String,
    pub status: PolicyStatus,
    pub required_scopes: BTreeSet<CovenantScope>,
    pub rule_commitments: Vec<String>,
    pub covenant_root: String,
    pub issuer_pq_root: String,
    pub holder_pq_root: String,
    pub mint_limit_commitment: String,
    pub burn_limit_commitment: String,
    pub transfer_limit_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: Option<String>,
    pub created_at_height: u64,
}

impl CovenantPolicy {
    pub fn record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "token_id": self.token_id,
            "token_class": self.token_class.as_str(),
            "issuer_commitment": self.issuer_commitment,
            "status": self.status.as_str(),
            "required_scopes": string_set(self.required_scopes.iter().map(|scope| scope.as_str())),
            "rule_commitments": self.rule_commitments,
            "covenant_root": self.covenant_root,
            "issuer_pq_root": self.issuer_pq_root,
            "holder_pq_root": self.holder_pq_root,
            "mint_limit_commitment": self.mint_limit_commitment,
            "burn_limit_commitment": self.burn_limit_commitment,
            "transfer_limit_commitment": self.transfer_limit_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "metadata_commitment": self.metadata_commitment,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCovenantProof {
    pub proof_id: String,
    pub policy_id: String,
    pub subject: ProofSubject,
    pub subject_commitment: String,
    pub pq_public_key_commitment: String,
    pub proof_root: String,
    pub signature_root: String,
    pub membership_root: String,
    pub nullifier_domain: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: ProofStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqCovenantProof {
    pub fn record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "policy_id": self.policy_id,
            "subject": self.subject.as_str(),
            "subject_commitment": self.subject_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "proof_root": self.proof_root,
            "signature_root": self.signature_root,
            "membership_root": self.membership_root,
            "nullifier_domain": self.nullifier_domain,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantCheck {
    pub check_id: String,
    pub policy_id: String,
    pub operation: OperationKind,
    pub verdict: CovenantVerdict,
    pub proof_ids: Vec<String>,
    pub nullifier_ids: Vec<String>,
    pub hook_ids: Vec<String>,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub transcript_root: String,
    pub created_at_height: u64,
}

impl CovenantCheck {
    pub fn record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "policy_id": self.policy_id,
            "operation": self.operation.as_str(),
            "verdict": self.verdict.as_str(),
            "proof_ids": self.proof_ids,
            "nullifier_ids": self.nullifier_ids,
            "hook_ids": self.hook_ids,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "transcript_root": self.transcript_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceNullifier {
    pub nullifier: String,
    pub policy_id: String,
    pub operation: OperationKind,
    pub bound_check_id: String,
    pub witness_root: String,
    pub disclosure_commitment: Option<String>,
    pub created_at_height: u64,
}

impl ComplianceNullifier {
    pub fn record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "policy_id": self.policy_id,
            "operation": self.operation.as_str(),
            "bound_check_id": self.bound_check_id,
            "witness_root": self.witness_root,
            "disclosure_commitment": self.disclosure_commitment,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractHookCommitment {
    pub hook_id: String,
    pub policy_id: String,
    pub hook_kind: HookKind,
    pub contract_commitment: String,
    pub method_selector_commitment: String,
    pub calldata_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub pq_authorization_root: String,
    pub privacy_budget_commitment: String,
    pub expires_at_height: u64,
    pub created_at_height: u64,
}

impl ContractHookCommitment {
    pub fn record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "policy_id": self.policy_id,
            "hook_kind": self.hook_kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "method_selector_commitment": self.method_selector_commitment,
            "calldata_root": self.calldata_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_budget_commitment": self.privacy_budget_commitment,
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchSettlement {
    pub settlement_id: String,
    pub status: SettlementStatus,
    pub operator_commitment: String,
    pub batch_root: String,
    pub claimed_batch_root: String,
    pub recursive_proof_root: String,
    pub da_commitment: String,
    pub fee_commitment_root: String,
    pub settlement_height: u64,
    pub finalizes_at_height: u64,
    pub item_count: u64,
    pub privacy_set_size: u64,
}

impl BatchSettlement {
    pub fn record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "batch_root": self.batch_root,
            "claimed_batch_root": self.claimed_batch_root,
            "recursive_proof_root": self.recursive_proof_root,
            "da_commitment": self.da_commitment,
            "fee_commitment_root": self.fee_commitment_root,
            "settlement_height": self.settlement_height,
            "finalizes_at_height": self.finalizes_at_height,
            "item_count": self.item_count,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorship {
    pub sponsor_id: String,
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub budget_commitment: String,
    pub fee_asset_id: String,
    pub sponsor_fee_bps: u64,
    pub status: FeeSponsorshipStatus,
    pub applies_to_root: String,
    pub pq_authorization_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub applied_check_id: Option<String>,
}

impl FeeSponsorship {
    pub fn record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "policy_id": self.policy_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_commitment": self.budget_commitment,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "status": self.status.as_str(),
            "applies_to_root": self.applies_to_root,
            "pq_authorization_root": self.pq_authorization_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "applied_check_id": self.applied_check_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub sponsor_id: Option<String>,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub proof_root: String,
    pub issued_at_height: u64,
}

impl FeeRebate {
    pub fn record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "settlement_id": self.settlement_id,
            "sponsor_id": self.sponsor_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_bps": self.rebate_bps,
            "proof_root": self.proof_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashRecord {
    pub slash_id: String,
    pub proof_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slashed_stake_commitment: String,
    pub slash_bps: u64,
    pub created_at_height: u64,
}

impl SlashRecord {
    pub fn record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "proof_id": self.proof_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "slashed_stake_commitment": self.slashed_stake_commitment,
            "slash_bps": self.slash_bps,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub operation: OperationKind,
    pub object_id: String,
    pub payload_commitment: String,
    pub state_root_after: String,
    pub height: u64,
    pub ordinal: u64,
}

impl RuntimeEvent {
    pub fn record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "operation": self.operation.as_str(),
            "object_id": self.object_id,
            "payload_commitment": self.payload_commitment,
            "state_root_after": self.state_root_after,
            "height": self.height,
            "ordinal": self.ordinal,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPolicyRequest {
    pub token_id: String,
    pub token_class: TokenClass,
    pub issuer_commitment: String,
    pub required_scopes: BTreeSet<CovenantScope>,
    pub rule_commitments: Vec<String>,
    pub issuer_pq_root: String,
    pub holder_pq_root: String,
    pub mint_limit_commitment: String,
    pub burn_limit_commitment: String,
    pub transfer_limit_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqProofRequest {
    pub policy_id: String,
    pub subject: ProofSubject,
    pub subject_commitment: String,
    pub pq_public_key_commitment: String,
    pub proof_root: String,
    pub signature_root: String,
    pub membership_root: String,
    pub nullifier_domain: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MintCovenantRequest {
    pub policy_id: String,
    pub issuer_proof_id: String,
    pub recipient_commitment: String,
    pub amount_commitment: String,
    pub mint_nullifier: String,
    pub hook_ids: Vec<String>,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub transcript_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BurnCovenantRequest {
    pub policy_id: String,
    pub holder_proof_id: String,
    pub holder_commitment: String,
    pub amount_commitment: String,
    pub burn_nullifier: String,
    pub hook_ids: Vec<String>,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub transcript_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferCovenantRequest {
    pub policy_id: String,
    pub sender_proof_id: String,
    pub recipient_proof_id: Option<String>,
    pub sender_commitment: String,
    pub recipient_commitment: String,
    pub amount_commitment: String,
    pub spend_nullifier: String,
    pub hook_ids: Vec<String>,
    pub sponsor_id: Option<String>,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub transcript_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceNullifierRequest {
    pub policy_id: String,
    pub operation: OperationKind,
    pub nullifier: String,
    pub witness_root: String,
    pub disclosure_commitment: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractHookRequest {
    pub policy_id: String,
    pub hook_kind: HookKind,
    pub contract_commitment: String,
    pub method_selector_commitment: String,
    pub calldata_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub pq_authorization_root: String,
    pub privacy_budget_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchSettlementRequest {
    pub operator_commitment: String,
    pub checks: Vec<CovenantCheck>,
    pub claimed_batch_root: String,
    pub recursive_proof_root: String,
    pub da_commitment: String,
    pub fee_commitment_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorshipRequest {
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub budget_commitment: String,
    pub fee_asset_id: String,
    pub sponsor_fee_bps: u64,
    pub applies_to_root: String,
    pub pq_authorization_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRequest {
    pub settlement_id: String,
    pub sponsor_id: Option<String>,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashAttestationRequest {
    pub proof_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slashed_stake_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantFeeQuoteRequest {
    pub policy_id: String,
    pub operation: OperationKind,
    pub requested_fee_bps: u64,
    pub privacy_set_size: u64,
    pub sponsor_available: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantFeeQuote {
    pub quote_id: String,
    pub policy_id: String,
    pub operation: OperationKind,
    pub requested_fee_bps: u64,
    pub capped_user_fee_bps: u64,
    pub sponsor_discount_bps: u64,
    pub effective_fee_bps: u64,
    pub privacy_multiplier_bps: u64,
    pub verdict: CovenantVerdict,
    pub expires_at_height: u64,
}

impl CovenantFeeQuote {
    pub fn record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "policy_id": self.policy_id,
            "operation": self.operation.as_str(),
            "requested_fee_bps": self.requested_fee_bps,
            "capped_user_fee_bps": self.capped_user_fee_bps,
            "sponsor_discount_bps": self.sponsor_discount_bps,
            "effective_fee_bps": self.effective_fee_bps,
            "privacy_multiplier_bps": self.privacy_multiplier_bps,
            "verdict": self.verdict.as_str(),
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyInspection {
    pub policy_id: String,
    pub token_id: String,
    pub status: PolicyStatus,
    pub covenant_root: String,
    pub issuer_proof_count: u64,
    pub holder_proof_count: u64,
    pub nullifier_count: u64,
    pub hook_count: u64,
    pub sponsor_count: u64,
    pub expired: bool,
    pub accepts_activity: bool,
    pub state_root: String,
}

impl PolicyInspection {
    pub fn record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "token_id": self.token_id,
            "status": self.status.as_str(),
            "covenant_root": self.covenant_root,
            "issuer_proof_count": self.issuer_proof_count,
            "holder_proof_count": self.holder_proof_count,
            "nullifier_count": self.nullifier_count,
            "hook_count": self.hook_count,
            "sponsor_count": self.sponsor_count,
            "expired": self.expired,
            "accepts_activity": self.accepts_activity,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpiryReport {
    pub expired_policies: u64,
    pub expired_proofs: u64,
    pub expired_hooks: u64,
    pub expired_sponsorships: u64,
    pub state_root: String,
}

impl ExpiryReport {
    pub fn record(&self) -> Value {
        json!({
            "expired_policies": self.expired_policies,
            "expired_proofs": self.expired_proofs,
            "expired_hooks": self.expired_hooks,
            "expired_sponsorships": self.expired_sponsorships,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantActivitySummary {
    pub height: u64,
    pub active_policies: u64,
    pub usable_proofs: u64,
    pub consumed_nullifiers: u64,
    pub live_hooks: u64,
    pub open_sponsorships: u64,
    pub unsettled_batches: u64,
    pub slash_count: u64,
    pub state_root: String,
}

impl CovenantActivitySummary {
    pub fn record(&self) -> Value {
        json!({
            "height": self.height,
            "active_policies": self.active_policies,
            "usable_proofs": self.usable_proofs,
            "consumed_nullifiers": self.consumed_nullifiers,
            "live_hooks": self.live_hooks,
            "open_sponsorships": self.open_sponsorships,
            "unsettled_batches": self.unsettled_batches,
            "slash_count": self.slash_count,
            "state_root": self.state_root,
        })
    }
}

pub fn policy_id(request: &RegisterPolicyRequest) -> String {
    digest_json(
        "PQL2-COVENANT-POLICY-ID",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "token_id": request.token_id,
            "token_class": request.token_class.as_str(),
            "issuer_commitment": request.issuer_commitment,
            "required_scopes": string_set(request.required_scopes.iter().map(|scope| scope.as_str())),
            "rule_commitments": request.rule_commitments,
            "issuer_pq_root": request.issuer_pq_root,
            "holder_pq_root": request.holder_pq_root,
        }),
    )
}

pub fn proof_id(request: &AttachPqProofRequest) -> String {
    digest_json(
        "PQL2-COVENANT-PROOF-ID",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": request.policy_id,
            "subject": request.subject.as_str(),
            "subject_commitment": request.subject_commitment,
            "pq_public_key_commitment": request.pq_public_key_commitment,
            "proof_root": request.proof_root,
            "signature_root": request.signature_root,
            "membership_root": request.membership_root,
            "nullifier_domain": request.nullifier_domain,
        }),
    )
}

pub fn hook_id(request: &ContractHookRequest, height: u64) -> String {
    digest_json(
        "PQL2-COVENANT-HOOK-ID",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": request.policy_id,
            "hook_kind": request.hook_kind.as_str(),
            "contract_commitment": request.contract_commitment,
            "method_selector_commitment": request.method_selector_commitment,
            "calldata_root": request.calldata_root,
            "height": height,
        }),
    )
}

pub fn settlement_id(request: &BatchSettlementRequest, height: u64) -> String {
    digest_json(
        "PQL2-COVENANT-SETTLEMENT-ID",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "operator_commitment": request.operator_commitment,
            "claimed_batch_root": request.claimed_batch_root,
            "recursive_proof_root": request.recursive_proof_root,
            "height": height,
        }),
    )
}

pub fn sponsor_id(request: &FeeSponsorshipRequest, height: u64) -> String {
    digest_json(
        "PQL2-COVENANT-SPONSOR-ID",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": request.policy_id,
            "sponsor_commitment": request.sponsor_commitment,
            "budget_commitment": request.budget_commitment,
            "applies_to_root": request.applies_to_root,
            "height": height,
        }),
    )
}

pub fn rebate_id(request: &FeeRebateRequest, height: u64) -> String {
    digest_json(
        "PQL2-COVENANT-REBATE-ID",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "settlement_id": request.settlement_id,
            "sponsor_id": request.sponsor_id,
            "recipient_commitment": request.recipient_commitment,
            "rebate_commitment": request.rebate_commitment,
            "height": height,
        }),
    )
}

pub fn slash_id(request: &SlashAttestationRequest, height: u64) -> String {
    digest_json(
        "PQL2-COVENANT-SLASH-ID",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "proof_id": request.proof_id,
            "reason": request.reason.as_str(),
            "evidence_root": request.evidence_root,
            "challenger_commitment": request.challenger_commitment,
            "height": height,
        }),
    )
}

pub fn covenant_root(scopes: &BTreeSet<CovenantScope>, rule_commitments: &[String]) -> String {
    merkle_root(
        "PQL2-COVENANT-RULESET",
        &[
            json!({
                "kind": "scopes",
                "values": string_set(scopes.iter().map(|scope| scope.as_str())),
            }),
            json!({
                "kind": "rules",
                "values": rule_commitments,
            }),
        ],
    )
}

pub fn check_root(checks: &[CovenantCheck]) -> String {
    let leaves = checks.iter().map(CovenantCheck::record).collect::<Vec<_>>();
    merkle_root("PQL2-COVENANT-CHECK-ROOT", &leaves)
}

pub fn operation_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn digest_json(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn digest_text(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn event_id(operation: OperationKind, object_id: &str, height: u64, ordinal: u64) -> String {
    domain_hash(
        "PQL2-COVENANT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operation.as_str()),
            HashPart::Str(object_id),
            HashPart::U64(height),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn privacy_multiplier_bps(privacy_set_size: u64, floor: u64) -> u64 {
    if floor == 0 || privacy_set_size >= floor.saturating_mul(8) {
        MAX_BPS
    } else if privacy_set_size >= floor.saturating_mul(4) {
        9_000
    } else if privacy_set_size >= floor.saturating_mul(2) {
        9_500
    } else {
        MAX_BPS
    }
}

fn optional_json_commitment(domain: &str, value: Option<&Value>) -> Option<String> {
    value.map(|payload| digest_json(domain, payload))
}

fn record_root<'a, T, I>(domain: &str, records: I) -> String
where
    T: RuntimeRecord + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let leaves = records
        .into_iter()
        .map(RuntimeRecord::record)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn index_root(domain: &str, index: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = index
        .iter()
        .map(|(key, values)| {
            json!({
                "key": key,
                "values": values.iter().cloned().collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_set<'a, I>(values: I) -> Vec<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    values.into_iter().collect::<Vec<_>>()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_eq(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{field} mismatch: expected {expected}, got {actual}"
        ))
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    ensure(value <= MAX_BPS, &format!("{field} exceeds {MAX_BPS} bps"))
}

fn ensure_nonzero(field: &str, value: u64) -> Result<()> {
    ensure(value > 0, &format!("{field} must be nonzero"))
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{field} must be nonempty"),
    )
}

fn ensure_capacity(field: &str, current: usize, max: usize) -> Result<()> {
    ensure(current < max, &format!("{field} capacity exhausted"))
}

fn ensure_absent<T>(map: &BTreeMap<String, T>, field: &str, id: &str) -> Result<()> {
    ensure(
        !map.contains_key(id),
        &format!("{field} already exists: {id}"),
    )
}

trait RuntimeRecord {
    fn record(&self) -> Value;
}

impl RuntimeRecord for CovenantPolicy {
    fn record(&self) -> Value {
        CovenantPolicy::record(self)
    }
}

impl RuntimeRecord for PqCovenantProof {
    fn record(&self) -> Value {
        PqCovenantProof::record(self)
    }
}

impl RuntimeRecord for ComplianceNullifier {
    fn record(&self) -> Value {
        ComplianceNullifier::record(self)
    }
}

impl RuntimeRecord for ContractHookCommitment {
    fn record(&self) -> Value {
        ContractHookCommitment::record(self)
    }
}

impl RuntimeRecord for BatchSettlement {
    fn record(&self) -> Value {
        BatchSettlement::record(self)
    }
}

impl RuntimeRecord for FeeSponsorship {
    fn record(&self) -> Value {
        FeeSponsorship::record(self)
    }
}

impl RuntimeRecord for FeeRebate {
    fn record(&self) -> Value {
        FeeRebate::record(self)
    }
}

impl RuntimeRecord for SlashRecord {
    fn record(&self) -> Value {
        SlashRecord::record(self)
    }
}

impl RuntimeRecord for RuntimeEvent {
    fn record(&self) -> Value {
        RuntimeEvent::record(self)
    }
}

impl RuntimeRecord for CovenantFeeQuote {
    fn record(&self) -> Value {
        CovenantFeeQuote::record(self)
    }
}

impl RuntimeRecord for PolicyInspection {
    fn record(&self) -> Value {
        PolicyInspection::record(self)
    }
}

impl RuntimeRecord for ExpiryReport {
    fn record(&self) -> Value {
        ExpiryReport::record(self)
    }
}

impl RuntimeRecord for CovenantActivitySummary {
    fn record(&self) -> Value {
        CovenantActivitySummary::record(self)
    }
}
