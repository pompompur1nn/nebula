use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageLiveReceiptCrossDomainRootAggregatorRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_LIVE_RECEIPT_CROSS_DOMAIN_ROOT_AGGREGATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-live-receipt-cross-domain-root-aggregator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_LIVE_RECEIPT_CROSS_DOMAIN_ROOT_AGGREGATOR_RUNTIME_PROTOCOL_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const AGGREGATOR_SUITE: &str =
    "force-exit-package-live-receipt-cross-domain-root-aggregator-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-devnet-v1";
pub const DEFAULT_FORCE_EXIT_PACKAGE_ID: &str =
    "force-exit-package-live-receipt-cross-domain-root-aggregator-devnet-0001";
pub const DEFAULT_RECEIPT_EPOCH: u64 = 77;
pub const DEFAULT_SOURCE_HEIGHT: u64 = 2_771_477;
pub const DEFAULT_L2_HEIGHT: u64 = 884_277;
pub const DEFAULT_MIN_ACCEPTED_DOMAINS: u16 = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDomain {
    Compile,
    Runtime,
    Audit,
    Bridge,
    Wallet,
    Watchtower,
    Pq,
    Reserve,
}

impl ReceiptDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Runtime => "runtime",
            Self::Audit => "audit",
            Self::Bridge => "bridge",
            Self::Wallet => "wallet",
            Self::Watchtower => "watchtower",
            Self::Pq => "pq",
            Self::Reserve => "reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainAcceptanceStatus {
    Accepted,
    Mismatch,
    Missing,
}

impl DomainAcceptanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Mismatch => "mismatch",
            Self::Missing => "missing",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedStatus {
    Open,
    ClosedByMismatch,
    ClosedByMissingDomain,
    ClosedByPolicy,
}

impl FailClosedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ClosedByMismatch => "closed_by_mismatch",
            Self::ClosedByMissingDomain => "closed_by_missing_domain",
            Self::ClosedByPolicy => "closed_by_policy",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub aggregator_suite: String,
    pub vertical_slice_id: String,
    pub force_exit_package_id: String,
    pub receipt_epoch: u64,
    pub source_height: u64,
    pub l2_height: u64,
    pub min_accepted_domains: u16,
    pub fail_closed_on_mismatch: bool,
    pub fail_closed_on_missing_domain: bool,
    pub require_release_policy_binding: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            aggregator_suite: AGGREGATOR_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            force_exit_package_id: DEFAULT_FORCE_EXIT_PACKAGE_ID.to_string(),
            receipt_epoch: DEFAULT_RECEIPT_EPOCH,
            source_height: DEFAULT_SOURCE_HEIGHT,
            l2_height: DEFAULT_L2_HEIGHT,
            min_accepted_domains: DEFAULT_MIN_ACCEPTED_DOMAINS,
            fail_closed_on_mismatch: true,
            fail_closed_on_missing_domain: true,
            require_release_policy_binding: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "aggregator_suite": self.aggregator_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "force_exit_package_id": self.force_exit_package_id,
            "receipt_epoch": self.receipt_epoch,
            "source_height": self.source_height,
            "l2_height": self.l2_height,
            "min_accepted_domains": self.min_accepted_domains,
            "fail_closed_on_mismatch": self.fail_closed_on_mismatch,
            "fail_closed_on_missing_domain": self.fail_closed_on_missing_domain,
            "require_release_policy_binding": self.require_release_policy_binding,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DomainReceipt {
    pub domain: ReceiptDomain,
    pub receipt_root: String,
    pub expected_receipt_root: String,
    pub acceptance_root: String,
    pub mismatch_root: String,
    pub status: DomainAcceptanceStatus,
    pub observer_set_root: String,
}

impl DomainReceipt {
    pub fn accepted(domain: ReceiptDomain, config: &Config, observer_set_root: &str) -> Self {
        let receipt_root = receipt_root(domain, config);
        let acceptance_root = acceptance_root(domain, &receipt_root, &receipt_root);
        Self {
            domain,
            receipt_root: receipt_root.clone(),
            expected_receipt_root: receipt_root,
            acceptance_root,
            mismatch_root: empty_root("MISMATCH"),
            status: DomainAcceptanceStatus::Accepted,
            observer_set_root: observer_set_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "domain": self.domain.as_str(),
            "receipt_root": self.receipt_root,
            "expected_receipt_root": self.expected_receipt_root,
            "acceptance_root": self.acceptance_root,
            "mismatch_root": self.mismatch_root,
            "status": self.status.as_str(),
            "observer_set_root": self.observer_set_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DOMAIN-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub compile_receipt_root: String,
    pub runtime_receipt_root: String,
    pub audit_receipt_root: String,
    pub bridge_receipt_root: String,
    pub wallet_receipt_root: String,
    pub watchtower_receipt_root: String,
    pub pq_receipt_root: String,
    pub reserve_receipt_root: String,
    pub compile_acceptance_root: String,
    pub runtime_acceptance_root: String,
    pub audit_acceptance_root: String,
    pub bridge_acceptance_root: String,
    pub wallet_acceptance_root: String,
    pub watchtower_acceptance_root: String,
    pub pq_acceptance_root: String,
    pub reserve_acceptance_root: String,
    pub mismatch_root: String,
    pub aggregate_release_root: String,
    pub release_policy_binding_root: String,
    pub fail_closed_status_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "compile_receipt_root": self.compile_receipt_root,
            "runtime_receipt_root": self.runtime_receipt_root,
            "audit_receipt_root": self.audit_receipt_root,
            "bridge_receipt_root": self.bridge_receipt_root,
            "wallet_receipt_root": self.wallet_receipt_root,
            "watchtower_receipt_root": self.watchtower_receipt_root,
            "pq_receipt_root": self.pq_receipt_root,
            "reserve_receipt_root": self.reserve_receipt_root,
            "compile_acceptance_root": self.compile_acceptance_root,
            "runtime_acceptance_root": self.runtime_acceptance_root,
            "audit_acceptance_root": self.audit_acceptance_root,
            "bridge_acceptance_root": self.bridge_acceptance_root,
            "wallet_acceptance_root": self.wallet_acceptance_root,
            "watchtower_acceptance_root": self.watchtower_acceptance_root,
            "pq_acceptance_root": self.pq_acceptance_root,
            "reserve_acceptance_root": self.reserve_acceptance_root,
            "mismatch_root": self.mismatch_root,
            "aggregate_release_root": self.aggregate_release_root,
            "release_policy_binding_root": self.release_policy_binding_root,
            "fail_closed_status_root": self.fail_closed_status_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Counters {
    pub domain_count: u16,
    pub accepted_domain_count: u16,
    pub mismatch_domain_count: u16,
    pub missing_domain_count: u16,
    pub release_ready_count: u16,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "domain_count": self.domain_count,
            "accepted_domain_count": self.accepted_domain_count,
            "mismatch_domain_count": self.mismatch_domain_count,
            "missing_domain_count": self.missing_domain_count,
            "release_ready_count": self.release_ready_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub receipts: Vec<DomainReceipt>,
    pub roots: Roots,
    pub counters: Counters,
    pub fail_closed_status: FailClosedStatus,
    pub release_permitted: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let observer_set_root = observer_set_root(&config);
        let receipts = [
            ReceiptDomain::Compile,
            ReceiptDomain::Runtime,
            ReceiptDomain::Audit,
            ReceiptDomain::Bridge,
            ReceiptDomain::Wallet,
            ReceiptDomain::Watchtower,
            ReceiptDomain::Pq,
            ReceiptDomain::Reserve,
        ]
        .into_iter()
        .map(|domain| DomainReceipt::accepted(domain, &config, &observer_set_root))
        .collect::<Vec<_>>();

        Self::from_receipts(config, receipts)
    }

    pub fn from_receipts(config: Config, receipts: Vec<DomainReceipt>) -> Self {
        let counters = counters_from_receipts(&receipts);
        let fail_closed_status = fail_closed_status(&config, &counters);
        let release_policy_binding_root =
            release_policy_binding_root(&config, &counters, fail_closed_status);
        let aggregate_release_root =
            aggregate_release_root(&config, &receipts, &release_policy_binding_root);
        let roots = roots_from_receipts(
            &receipts,
            &aggregate_release_root,
            &release_policy_binding_root,
            fail_closed_status,
        );
        let release_permitted = fail_closed_status.permits_release()
            && counters.accepted_domain_count >= config.min_accepted_domains
            && roots.release_policy_binding_root == release_policy_binding_root;

        Self {
            config,
            receipts,
            roots,
            counters,
            fail_closed_status,
            release_permitted,
        }
    }

    pub fn public_record(&self) -> Value {
        let receipts = self
            .receipts
            .iter()
            .map(DomainReceipt::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "receipts": receipts,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "fail_closed_status": self.fail_closed_status.as_str(),
            "release_permitted": self.release_permitted,
        })
    }

    pub fn state_root(&self) -> String {
        let record = self.public_record();
        domain_hash(
            "MFE-LIVE-RECEIPT-CROSS-DOMAIN-ROOT-AGGREGATOR-STATE",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&record)],
            32,
        )
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

fn counters_from_receipts(receipts: &[DomainReceipt]) -> Counters {
    let domain_count = receipts.len() as u16;
    let accepted_domain_count = receipts
        .iter()
        .filter(|receipt| receipt.status.permits_release())
        .count() as u16;
    let mismatch_domain_count = receipts
        .iter()
        .filter(|receipt| matches!(receipt.status, DomainAcceptanceStatus::Mismatch))
        .count() as u16;
    let missing_domain_count = receipts
        .iter()
        .filter(|receipt| matches!(receipt.status, DomainAcceptanceStatus::Missing))
        .count() as u16;
    Counters {
        domain_count,
        accepted_domain_count,
        mismatch_domain_count,
        missing_domain_count,
        release_ready_count: accepted_domain_count,
    }
}

fn fail_closed_status(config: &Config, counters: &Counters) -> FailClosedStatus {
    if config.fail_closed_on_mismatch && counters.mismatch_domain_count > 0 {
        FailClosedStatus::ClosedByMismatch
    } else if config.fail_closed_on_missing_domain && counters.missing_domain_count > 0 {
        FailClosedStatus::ClosedByMissingDomain
    } else if config.require_release_policy_binding
        && counters.accepted_domain_count < config.min_accepted_domains
    {
        FailClosedStatus::ClosedByPolicy
    } else {
        FailClosedStatus::Open
    }
}

fn roots_from_receipts(
    receipts: &[DomainReceipt],
    aggregate_release_root: &str,
    release_policy_binding_root: &str,
    fail_closed_status: FailClosedStatus,
) -> Roots {
    Roots {
        compile_receipt_root: domain_field(receipts, ReceiptDomain::Compile, DomainField::Receipt),
        runtime_receipt_root: domain_field(receipts, ReceiptDomain::Runtime, DomainField::Receipt),
        audit_receipt_root: domain_field(receipts, ReceiptDomain::Audit, DomainField::Receipt),
        bridge_receipt_root: domain_field(receipts, ReceiptDomain::Bridge, DomainField::Receipt),
        wallet_receipt_root: domain_field(receipts, ReceiptDomain::Wallet, DomainField::Receipt),
        watchtower_receipt_root: domain_field(
            receipts,
            ReceiptDomain::Watchtower,
            DomainField::Receipt,
        ),
        pq_receipt_root: domain_field(receipts, ReceiptDomain::Pq, DomainField::Receipt),
        reserve_receipt_root: domain_field(receipts, ReceiptDomain::Reserve, DomainField::Receipt),
        compile_acceptance_root: domain_field(
            receipts,
            ReceiptDomain::Compile,
            DomainField::Acceptance,
        ),
        runtime_acceptance_root: domain_field(
            receipts,
            ReceiptDomain::Runtime,
            DomainField::Acceptance,
        ),
        audit_acceptance_root: domain_field(
            receipts,
            ReceiptDomain::Audit,
            DomainField::Acceptance,
        ),
        bridge_acceptance_root: domain_field(
            receipts,
            ReceiptDomain::Bridge,
            DomainField::Acceptance,
        ),
        wallet_acceptance_root: domain_field(
            receipts,
            ReceiptDomain::Wallet,
            DomainField::Acceptance,
        ),
        watchtower_acceptance_root: domain_field(
            receipts,
            ReceiptDomain::Watchtower,
            DomainField::Acceptance,
        ),
        pq_acceptance_root: domain_field(receipts, ReceiptDomain::Pq, DomainField::Acceptance),
        reserve_acceptance_root: domain_field(
            receipts,
            ReceiptDomain::Reserve,
            DomainField::Acceptance,
        ),
        mismatch_root: mismatch_root(receipts),
        aggregate_release_root: aggregate_release_root.to_string(),
        release_policy_binding_root: release_policy_binding_root.to_string(),
        fail_closed_status_root: fail_closed_status_root(fail_closed_status),
    }
}

#[derive(Clone, Copy)]
enum DomainField {
    Receipt,
    Acceptance,
}

fn domain_field(receipts: &[DomainReceipt], domain: ReceiptDomain, field: DomainField) -> String {
    receipts
        .iter()
        .find(|receipt| receipt.domain == domain)
        .map(|receipt| match field {
            DomainField::Receipt => receipt.receipt_root.clone(),
            DomainField::Acceptance => receipt.acceptance_root.clone(),
        })
        .unwrap_or_else(|| missing_domain_root(domain))
}

fn receipt_root(domain: ReceiptDomain, config: &Config) -> String {
    let record = json!({
        "chain_id": config.chain_id,
        "protocol_version": config.protocol_version,
        "vertical_slice_id": config.vertical_slice_id,
        "force_exit_package_id": config.force_exit_package_id,
        "receipt_epoch": config.receipt_epoch,
        "source_height": config.source_height,
        "l2_height": config.l2_height,
        "domain": domain.as_str(),
    });
    record_root("RECEIPT", &record)
}

fn acceptance_root(
    domain: ReceiptDomain,
    receipt_root: &str,
    expected_receipt_root: &str,
) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "domain": domain.as_str(),
        "receipt_root": receipt_root,
        "expected_receipt_root": expected_receipt_root,
        "accepted": receipt_root == expected_receipt_root,
    });
    record_root("ACCEPTANCE", &record)
}

fn mismatch_root(receipts: &[DomainReceipt]) -> String {
    let records = receipts
        .iter()
        .filter(|receipt| !receipt.status.permits_release())
        .map(|receipt| {
            json!({
                "domain": receipt.domain.as_str(),
                "receipt_root": receipt.receipt_root,
                "expected_receipt_root": receipt.expected_receipt_root,
                "mismatch_root": receipt.mismatch_root,
                "status": receipt.status.as_str(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("MFE-LIVE-RECEIPT-MISMATCH", &records)
}

fn aggregate_release_root(
    config: &Config,
    receipts: &[DomainReceipt],
    release_policy_binding_root: &str,
) -> String {
    let records = receipts
        .iter()
        .map(|receipt| {
            json!({
                "domain": receipt.domain.as_str(),
                "acceptance_root": receipt.acceptance_root,
                "receipt_root": receipt.receipt_root,
                "status": receipt.status.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let receipt_set_root = merkle_root("MFE-LIVE-RECEIPT-ACCEPTED-DOMAIN", &records);
    let record = json!({
        "chain_id": config.chain_id,
        "protocol_version": config.protocol_version,
        "force_exit_package_id": config.force_exit_package_id,
        "receipt_set_root": receipt_set_root,
        "release_policy_binding_root": release_policy_binding_root,
    });
    record_root("AGGREGATE-RELEASE", &record)
}

fn release_policy_binding_root(
    config: &Config,
    counters: &Counters,
    fail_closed_status: FailClosedStatus,
) -> String {
    let record = json!({
        "chain_id": config.chain_id,
        "protocol_version": config.protocol_version,
        "force_exit_package_id": config.force_exit_package_id,
        "min_accepted_domains": config.min_accepted_domains,
        "accepted_domain_count": counters.accepted_domain_count,
        "mismatch_domain_count": counters.mismatch_domain_count,
        "missing_domain_count": counters.missing_domain_count,
        "fail_closed_status": fail_closed_status.as_str(),
        "fail_closed_on_mismatch": config.fail_closed_on_mismatch,
        "fail_closed_on_missing_domain": config.fail_closed_on_missing_domain,
        "require_release_policy_binding": config.require_release_policy_binding,
    });
    record_root("RELEASE-POLICY-BINDING", &record)
}

fn fail_closed_status_root(status: FailClosedStatus) -> String {
    domain_hash(
        "MFE-LIVE-RECEIPT-FAIL-CLOSED-STATUS",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(status.as_str())],
        32,
    )
}

fn observer_set_root(config: &Config) -> String {
    let records = [
        "compile-receipt-builder",
        "runtime-receipt-replayer",
        "audit-receipt-signer",
        "bridge-receipt-indexer",
        "wallet-receipt-watcher",
        "watchtower-live-feed",
        "pq-attestation-quorum",
        "reserve-proof-oracle",
    ]
    .into_iter()
    .map(|observer| {
        json!({
            "chain_id": config.chain_id,
            "force_exit_package_id": config.force_exit_package_id,
            "observer": observer,
            "receipt_epoch": config.receipt_epoch,
        })
    })
    .collect::<Vec<_>>();
    merkle_root("MFE-LIVE-RECEIPT-OBSERVER-SET", &records)
}

fn missing_domain_root(domain: ReceiptDomain) -> String {
    domain_hash(
        "MFE-LIVE-RECEIPT-MISSING-DOMAIN",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(domain.as_str())],
        32,
    )
}

fn empty_root(label: &str) -> String {
    merkle_root(&format!("MFE-LIVE-RECEIPT-{label}"), &[])
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("MFE-LIVE-RECEIPT-CROSS-DOMAIN-ROOT-AGGREGATOR-{label}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}
