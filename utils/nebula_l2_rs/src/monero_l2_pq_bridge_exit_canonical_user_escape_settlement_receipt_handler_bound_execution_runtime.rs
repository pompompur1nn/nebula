use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptHandlerBoundExecutionRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-settlement-receipt-handler-bound-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTION_SUITE: &str = "handler-bound-forced-exit-settlement-receipt-continuity-v1";
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_FEE_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MIN_HANDLER_QUORUM: u64 = 3;

const DOMAIN: &str =
    "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-SETTLEMENT-RECEIPT-HANDLER-BOUND-EXECUTION-RUNTIME";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub execution_suite: String,
    pub challenge_window_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub max_fee_atomic: u128,
    pub min_handler_quorum: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            execution_suite: EXECUTION_SUITE.to_string(),
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            min_handler_quorum: DEFAULT_MIN_HANDLER_QUORUM,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "execution_suite": self.execution_suite,
            "challenge_window_blocks": self.challenge_window_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "max_fee_atomic": self.max_fee_atomic.to_string(),
            "min_handler_quorum": self.min_handler_quorum,
        })
    }

    pub fn root(&self) -> String {
        record_hash("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandlerBoundRoots {
    pub handler_id: String,
    pub handler_epoch: u64,
    pub handler_binding_root: String,
    pub handler_receipt_root: String,
    pub handler_quorum: u64,
}

impl HandlerBoundRoots {
    pub fn devnet(config: &Config) -> Self {
        let handler_id = short_hash("HANDLER-ID", "devnet-forced-exit-settlement-handler");
        Self {
            handler_binding_root: short_hash("HANDLER-BINDING", &handler_id),
            handler_receipt_root: short_hash("HANDLER-RECEIPT", &handler_id),
            handler_id,
            handler_epoch: 44,
            handler_quorum: config.min_handler_quorum,
        }
    }

    pub fn quorum_met(&self, config: &Config) -> bool {
        self.handler_quorum >= config.min_handler_quorum
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "handler_id": self.handler_id,
            "handler_epoch": self.handler_epoch,
            "handler_binding_root": self.handler_binding_root,
            "handler_receipt_root": self.handler_receipt_root,
            "handler_quorum": self.handler_quorum,
            "quorum_met": self.quorum_met(config),
        })
    }

    pub fn root(&self, config: &Config) -> String {
        record_hash("HANDLER-BOUND-ROOTS", &self.public_record(config))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptClaimRoots {
    pub settlement_receipt_root: String,
    pub encrypted_receipt_root: String,
    pub release_receipt_root: String,
    pub withdrawal_claim_root: String,
}

impl ReceiptClaimRoots {
    pub fn devnet(handler: &HandlerBoundRoots) -> Self {
        Self {
            settlement_receipt_root: short_hash("SETTLEMENT-RECEIPT", &handler.handler_id),
            encrypted_receipt_root: short_hash("ENCRYPTED-SETTLEMENT-RECEIPT", &handler.handler_id),
            release_receipt_root: short_hash("RELEASE-RECEIPT", &handler.handler_id),
            withdrawal_claim_root: short_hash("WITHDRAWAL-CLAIM", &handler.handler_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_receipt_root": self.settlement_receipt_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "release_receipt_root": self.release_receipt_root,
            "withdrawal_claim_root": self.withdrawal_claim_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("RECEIPT-CLAIM-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRoots {
    pub fee_quote_root: String,
    pub fee_receipt_root: String,
    pub quoted_fee_atomic: u128,
    pub charged_fee_atomic: u128,
}

impl FeeRoots {
    pub fn devnet(claims: &ReceiptClaimRoots) -> Self {
        Self {
            fee_quote_root: short_hash("FEE-QUOTE", &claims.withdrawal_claim_root),
            fee_receipt_root: short_hash("FEE-RECEIPT", &claims.settlement_receipt_root),
            quoted_fee_atomic: 18_000_000,
            charged_fee_atomic: 18_000_000,
        }
    }

    pub fn within_cap(&self, config: &Config) -> bool {
        self.charged_fee_atomic <= config.max_fee_atomic
            && self.charged_fee_atomic <= self.quoted_fee_atomic
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "fee_quote_root": self.fee_quote_root,
            "fee_receipt_root": self.fee_receipt_root,
            "quoted_fee_atomic": self.quoted_fee_atomic.to_string(),
            "charged_fee_atomic": self.charged_fee_atomic.to_string(),
            "max_fee_atomic": config.max_fee_atomic.to_string(),
            "within_cap": self.within_cap(config),
        })
    }

    pub fn root(&self, config: &Config) -> String {
        record_hash("FEE-ROOTS", &self.public_record(config))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeRoots {
    pub challenge_set_root: String,
    pub challenge_verdict_root: String,
    pub opened_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub current_l2_height: u64,
    pub unresolved_challenges: u64,
}

impl ChallengeRoots {
    pub fn devnet(config: &Config, claims: &ReceiptClaimRoots) -> Self {
        let opened_at_l2_height = 4_260_000;
        Self {
            challenge_set_root: short_hash("CHALLENGE-SET", &claims.withdrawal_claim_root),
            challenge_verdict_root: short_hash(
                "CHALLENGE-VERDICT",
                &claims.settlement_receipt_root,
            ),
            opened_at_l2_height,
            closes_at_l2_height: opened_at_l2_height + config.challenge_window_blocks,
            current_l2_height: opened_at_l2_height
                + config.challenge_window_blocks
                + config.settlement_finality_blocks
                + 4,
            unresolved_challenges: 0,
        }
    }

    pub fn elapsed(&self, config: &Config) -> bool {
        self.current_l2_height >= self.closes_at_l2_height + config.settlement_finality_blocks
            && self.unresolved_challenges == 0
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "challenge_set_root": self.challenge_set_root,
            "challenge_verdict_root": self.challenge_verdict_root,
            "opened_at_l2_height": self.opened_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height,
            "current_l2_height": self.current_l2_height,
            "settlement_finality_blocks": config.settlement_finality_blocks,
            "unresolved_challenges": self.unresolved_challenges,
            "elapsed": self.elapsed(config),
        })
    }

    pub fn root(&self, config: &Config) -> String {
        record_hash("CHALLENGE-ROOTS", &self.public_record(config))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalClaimRoots {
    pub claim_queue_root: String,
    pub claim_inclusion_root: String,
    pub nullifier_root: String,
    pub withdrawal_address_commitment_root: String,
}

impl WithdrawalClaimRoots {
    pub fn devnet(claims: &ReceiptClaimRoots) -> Self {
        Self {
            claim_queue_root: leaf_root(
                "WITHDRAWAL-CLAIM-QUEUE",
                &[
                    claims.withdrawal_claim_root.as_str(),
                    "forced-exit-claim:devnet:prior",
                    "forced-exit-claim:devnet:tail",
                ],
            ),
            claim_inclusion_root: short_hash("CLAIM-INCLUSION", &claims.withdrawal_claim_root),
            nullifier_root: short_hash("CLAIM-NULLIFIER", &claims.withdrawal_claim_root),
            withdrawal_address_commitment_root: short_hash(
                "WITHDRAWAL-ADDRESS-COMMITMENT",
                &claims.withdrawal_claim_root,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_queue_root": self.claim_queue_root,
            "claim_inclusion_root": self.claim_inclusion_root,
            "nullifier_root": self.nullifier_root,
            "withdrawal_address_commitment_root": self.withdrawal_address_commitment_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-CLAIM-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContinuityVerdict {
    pub verdict: String,
    pub release_allowed: bool,
    pub handler_bound: bool,
    pub receipt_claim_continuous: bool,
    pub fee_continuous: bool,
    pub challenge_continuous: bool,
    pub withdrawal_claim_continuous: bool,
    pub verdict_root: String,
}

impl ContinuityVerdict {
    pub fn evaluate(
        config: &Config,
        handler: &HandlerBoundRoots,
        claims: &ReceiptClaimRoots,
        fees: &FeeRoots,
        challenges: &ChallengeRoots,
        withdrawals: &WithdrawalClaimRoots,
    ) -> Self {
        let handler_bound = handler.quorum_met(config);
        let receipt_claim_continuous = claims.withdrawal_claim_root
            != claims.settlement_receipt_root
            && claims.release_receipt_root != claims.encrypted_receipt_root;
        let fee_continuous = fees.within_cap(config);
        let challenge_continuous = challenges.elapsed(config);
        let withdrawal_claim_continuous = withdrawals.claim_queue_root
            != withdrawals.nullifier_root
            && withdrawals.claim_inclusion_root != withdrawals.withdrawal_address_commitment_root;
        let release_allowed = handler_bound
            && receipt_claim_continuous
            && fee_continuous
            && challenge_continuous
            && withdrawal_claim_continuous;
        let verdict = if release_allowed {
            "continuity_accepted"
        } else {
            "continuity_rejected"
        }
        .to_string();
        let verdict_root = verdict_digest(
            &verdict,
            release_allowed,
            handler_bound,
            receipt_claim_continuous,
            fee_continuous,
            challenge_continuous,
            withdrawal_claim_continuous,
        );

        Self {
            verdict,
            release_allowed,
            handler_bound,
            receipt_claim_continuous,
            fee_continuous,
            challenge_continuous,
            withdrawal_claim_continuous,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict,
            "release_allowed": self.release_allowed,
            "handler_bound": self.handler_bound,
            "receipt_claim_continuous": self.receipt_claim_continuous,
            "fee_continuous": self.fee_continuous,
            "challenge_continuous": self.challenge_continuous,
            "withdrawal_claim_continuous": self.withdrawal_claim_continuous,
            "verdict_root": self.verdict_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("CONTINUITY-VERDICT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub handler_bound_roots: HandlerBoundRoots,
    pub receipt_claim_roots: ReceiptClaimRoots,
    pub fee_roots: FeeRoots,
    pub challenge_roots: ChallengeRoots,
    pub withdrawal_claim_roots: WithdrawalClaimRoots,
    pub continuity_verdict: ContinuityVerdict,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let handler_bound_roots = HandlerBoundRoots::devnet(&config);
        let receipt_claim_roots = ReceiptClaimRoots::devnet(&handler_bound_roots);
        let fee_roots = FeeRoots::devnet(&receipt_claim_roots);
        let challenge_roots = ChallengeRoots::devnet(&config, &receipt_claim_roots);
        let withdrawal_claim_roots = WithdrawalClaimRoots::devnet(&receipt_claim_roots);
        let continuity_verdict = ContinuityVerdict::evaluate(
            &config,
            &handler_bound_roots,
            &receipt_claim_roots,
            &fee_roots,
            &challenge_roots,
            &withdrawal_claim_roots,
        );

        Self {
            config,
            handler_bound_roots,
            receipt_claim_roots,
            fee_roots,
            challenge_roots,
            withdrawal_claim_roots,
            continuity_verdict,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_handler_bound_execution_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "handler_bound_roots": self.handler_bound_roots.public_record(&self.config),
            "receipt_claim_roots": self.receipt_claim_roots.public_record(),
            "fee_roots": self.fee_roots.public_record(&self.config),
            "challenge_roots": self.challenge_roots.public_record(&self.config),
            "withdrawal_claim_roots": self.withdrawal_claim_roots.public_record(),
            "continuity_verdict": self.continuity_verdict.public_record(),
            "component_roots": self.component_roots(),
            "state_root": self.state_root(),
        })
    }

    pub fn component_roots(&self) -> Value {
        json!({
            "config_root": self.config.root(),
            "handler_bound_root": self.handler_bound_roots.root(&self.config),
            "receipt_claim_root": self.receipt_claim_roots.root(),
            "fee_root": self.fee_roots.root(&self.config),
            "challenge_root": self.challenge_roots.root(&self.config),
            "withdrawal_claim_root": self.withdrawal_claim_roots.root(),
            "continuity_verdict_root": self.continuity_verdict.root(),
        })
    }

    pub fn state_root(&self) -> String {
        let component_roots = self.component_roots();
        domain_hash(
            &format!("{DOMAIN}:STATE-ROOT"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&component_roots),
            ],
            32,
        )
    }

    pub fn root(&self) -> String {
        self.state_root()
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn record_hash(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn short_hash(label: &str, value: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn leaf_root(label: &str, leaves: &[&str]) -> String {
    let records = leaves
        .iter()
        .map(|leaf| {
            json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "leaf": leaf,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &records)
}

fn verdict_digest(
    verdict: &str,
    release_allowed: bool,
    handler_bound: bool,
    receipt_claim_continuous: bool,
    fee_continuous: bool,
    challenge_continuous: bool,
    withdrawal_claim_continuous: bool,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:VERDICT-DIGEST"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(verdict),
            HashPart::Str(bool_label(release_allowed)),
            HashPart::Str(bool_label(handler_bound)),
            HashPart::Str(bool_label(receipt_claim_continuous)),
            HashPart::Str(bool_label(fee_continuous)),
            HashPart::Str(bool_label(challenge_continuous)),
            HashPart::Str(bool_label(withdrawal_claim_continuous)),
        ],
        32,
    )
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
