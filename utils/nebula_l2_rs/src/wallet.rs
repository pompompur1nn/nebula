use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    contracts::{caller_commitment as contract_caller_commitment, ContractExecutionReceipt},
    defi::Note,
    hash::{domain_hash, merkle_root, HashPart},
    mempool::MempoolState,
    monero::{MoneroAnchorObservation, MoneroReorgEvidence, MoneroWithdrawalObservation},
    paymasters::{paymaster_caller_commitment, PaymasterSponsoredCall},
    runtime::{wasm_caller_commitment, WasmRuntimeExecutionReceipt},
    settlement::{
        BridgeDepositAddress, BridgeDepositObservation, BridgeMintRecord, BridgeWithdrawalRecord,
    },
    CHAIN_ID,
};

pub type WalletResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletScanRequest {
    pub owner_view_key: String,
    pub current_height: u64,
    pub watched_tx_hashes: Vec<String>,
    pub watched_nullifiers: Vec<String>,
}

impl WalletScanRequest {
    pub fn new(owner_view_key: impl Into<String>, current_height: u64) -> Self {
        Self {
            owner_view_key: owner_view_key.into(),
            current_height,
            watched_tx_hashes: Vec::new(),
            watched_nullifiers: Vec::new(),
        }
    }

    pub fn watch_tx_hash(mut self, tx_hash: impl Into<String>) -> Self {
        self.watched_tx_hashes.push(tx_hash.into());
        self
    }

    pub fn watch_nullifier(mut self, nullifier: impl Into<String>) -> Self {
        self.watched_nullifiers.push(nullifier.into());
        self
    }

    fn normalized_tx_hashes(&self) -> BTreeSet<String> {
        self.watched_tx_hashes.iter().cloned().collect()
    }

    fn normalized_nullifiers(&self) -> BTreeSet<String> {
        self.watched_nullifiers.iter().cloned().collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletHistoryRecord {
    pub history_id: String,
    pub scan_tag: String,
    pub kind: String,
    pub direction: String,
    pub status: String,
    pub height: u64,
    pub tx_hash: String,
    pub asset_id: String,
    pub amount: u64,
    pub amount_bucket: u64,
    pub commitment: String,
    pub nullifier: String,
    pub record_hash: String,
    pub record: Value,
}

impl WalletHistoryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "history_id": self.history_id,
            "scan_tag": self.scan_tag,
            "kind": self.kind,
            "direction": self.direction,
            "status": self.status,
            "height": self.height,
            "tx_hash": self.tx_hash,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "amount_bucket": self.amount_bucket,
            "commitment": self.commitment,
            "nullifier": self.nullifier,
            "record_hash": self.record_hash,
            "record": self.record,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletView {
    pub owner_commitment: String,
    pub contract_caller_commitment: String,
    pub wasm_caller_commitment: String,
    pub paymaster_caller_commitment: String,
    pub current_height: u64,
    pub watched_tx_hash_count: u64,
    pub watched_nullifier_count: u64,
    pub records: Vec<WalletHistoryRecord>,
}

impl WalletView {
    pub fn history_root(&self) -> String {
        merkle_root(
            "WALLET-HISTORY",
            &self
                .records
                .iter()
                .map(WalletHistoryRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "owner_commitment": self.owner_commitment,
            "contract_caller_commitment": self.contract_caller_commitment,
            "wasm_caller_commitment": self.wasm_caller_commitment,
            "paymaster_caller_commitment": self.paymaster_caller_commitment,
            "current_height": self.current_height,
            "watched_tx_hash_count": self.watched_tx_hash_count,
            "watched_nullifier_count": self.watched_nullifier_count,
            "history_count": self.records.len(),
            "history_root": self.history_root(),
            "records": self.records.iter().map(WalletHistoryRecord::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSyncIndex {
    records: Vec<WalletHistoryRecord>,
}

impl WalletSyncIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scan(
        self,
        request: WalletScanRequest,
        sources: WalletScanSources<'_>,
    ) -> WalletResult<WalletView> {
        self.scan_inner(request, sources, WalletMoneroEvidenceSources::default())
    }

    pub fn scan_with_monero_evidence(
        self,
        request: WalletScanRequest,
        sources: WalletScanSourcesWithMonero<'_>,
    ) -> WalletResult<WalletView> {
        self.scan_inner(request, sources.wallet_sources, sources.monero_evidence)
    }

    fn scan_inner(
        mut self,
        request: WalletScanRequest,
        sources: WalletScanSources<'_>,
        monero_evidence: WalletMoneroEvidenceSources<'_>,
    ) -> WalletResult<WalletView> {
        if request.owner_view_key.is_empty() {
            return Err("wallet owner_view_key is required".to_string());
        }
        let tx_hashes = request.normalized_tx_hashes();
        let nullifiers = request.normalized_nullifiers();
        let owner_commitment = wallet_owner_commitment(&request.owner_view_key);
        let contract_commitment = contract_caller_commitment(&request.owner_view_key);
        let wasm_commitment = wasm_caller_commitment(&request.owner_view_key);
        let paymaster_commitment = paymaster_caller_commitment(&request.owner_view_key);

        self.ingest_notes(&request.owner_view_key, sources.notes);
        self.ingest_mempool(&request.owner_view_key, &tx_hashes, sources.mempool);
        self.ingest_contract_receipts(
            &request.owner_view_key,
            &contract_commitment,
            sources.contract_receipts,
        );
        self.ingest_wasm_receipts(
            &request.owner_view_key,
            &wasm_commitment,
            sources.wasm_receipts,
        );
        let owned_withdrawal_ids = self.ingest_bridge(
            &request.owner_view_key,
            &nullifiers,
            sources.bridge_deposit_addresses,
            sources.bridge_deposit_observations,
            sources.bridge_mints,
            sources.bridge_withdrawals,
        );
        self.ingest_monero_evidence(
            &request.owner_view_key,
            &tx_hashes,
            &owned_withdrawal_ids,
            monero_evidence,
        );
        self.ingest_paymaster_sponsorships(
            &request.owner_view_key,
            &paymaster_commitment,
            sources.paymaster_sponsorships,
        );
        self.records.sort_by(|left, right| {
            (left.height, left.kind.as_str(), left.history_id.as_str()).cmp(&(
                right.height,
                right.kind.as_str(),
                right.history_id.as_str(),
            ))
        });

        Ok(WalletView {
            owner_commitment,
            contract_caller_commitment: contract_commitment,
            wasm_caller_commitment: wasm_commitment,
            paymaster_caller_commitment: paymaster_commitment,
            current_height: request.current_height,
            watched_tx_hash_count: tx_hashes.len() as u64,
            watched_nullifier_count: nullifiers.len() as u64,
            records: self.records,
        })
    }

    fn ingest_notes(&mut self, owner_view_key: &str, notes: &[Note]) {
        for note in notes
            .iter()
            .filter(|note| note.owner_view_key == owner_view_key)
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "note",
                direction: "inbound",
                status: "unspent",
                height: 0,
                tx_hash: "",
                asset_id: &note.asset_id,
                amount: note.amount,
                amount_bucket: wallet_amount_bucket(note.amount),
                commitment: &note.commitment,
                nullifier: "",
                record: note.wallet_record(),
            });
        }
    }

    fn ingest_mempool(
        &mut self,
        owner_view_key: &str,
        tx_hashes: &BTreeSet<String>,
        mempool: Option<&MempoolState>,
    ) {
        let Some(mempool) = mempool else {
            return;
        };
        for admission in mempool
            .pending_admissions
            .iter()
            .filter(|admission| tx_hashes.contains(&admission.tx_public_hash))
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "mempool_admission",
                direction: "pending",
                status: "pending",
                height: admission.admitted_at_height,
                tx_hash: &admission.tx_public_hash,
                asset_id: "",
                amount: 0,
                amount_bucket: 0,
                commitment: &admission.admission_id,
                nullifier: "",
                record: admission.public_record(),
            });
        }
        for preconfirmation in mempool
            .preconfirmations
            .values()
            .filter(|preconfirmation| tx_hashes.contains(&preconfirmation.tx_public_hash))
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "mempool_preconfirmation",
                direction: "pending",
                status: "preconfirmed",
                height: preconfirmation.preconfirmed_at_height,
                tx_hash: &preconfirmation.tx_public_hash,
                asset_id: "",
                amount: 0,
                amount_bucket: 0,
                commitment: &preconfirmation.preconfirmation_id,
                nullifier: "",
                record: preconfirmation.public_record(),
            });
        }
    }

    fn ingest_contract_receipts(
        &mut self,
        owner_view_key: &str,
        caller_commitment: &str,
        receipts: &[ContractExecutionReceipt],
    ) {
        for receipt in receipts
            .iter()
            .filter(|receipt| receipt.caller_commitment == caller_commitment)
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "contract_receipt",
                direction: "contract",
                status: "executed",
                height: receipt.block_height,
                tx_hash: &receipt.tx_hash,
                asset_id: "",
                amount: 0,
                amount_bucket: 0,
                commitment: &receipt.receipt_id,
                nullifier: "",
                record: receipt.public_record(),
            });
        }
    }

    fn ingest_wasm_receipts(
        &mut self,
        owner_view_key: &str,
        caller_commitment: &str,
        receipts: &[WasmRuntimeExecutionReceipt],
    ) {
        for receipt in receipts
            .iter()
            .filter(|receipt| receipt.caller_commitment == caller_commitment)
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "wasm_receipt",
                direction: "contract",
                status: "executed",
                height: 0,
                tx_hash: &receipt.tx_hash,
                asset_id: &receipt.fee_asset_id,
                amount: receipt.fee,
                amount_bucket: wallet_amount_bucket(receipt.fee),
                commitment: &receipt.receipt_id,
                nullifier: "",
                record: receipt.public_record(),
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_bridge(
        &mut self,
        owner_view_key: &str,
        nullifiers: &BTreeSet<String>,
        deposit_addresses: &[BridgeDepositAddress],
        observations: &[BridgeDepositObservation],
        mints: &[BridgeMintRecord],
        withdrawals: &[BridgeWithdrawalRecord],
    ) -> BTreeSet<String> {
        let owned_deposit_ids = deposit_addresses
            .iter()
            .filter(|address| address.recipient_view_key == owner_view_key)
            .map(|address| address.deposit_id.clone())
            .collect::<BTreeSet<_>>();
        let owned_withdrawal_ids = withdrawals
            .iter()
            .filter(|withdrawal| nullifiers.contains(&withdrawal.nullifier))
            .map(|withdrawal| withdrawal.withdrawal_id.clone())
            .collect::<BTreeSet<_>>();
        for address in deposit_addresses
            .iter()
            .filter(|address| owned_deposit_ids.contains(&address.deposit_id))
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "bridge_deposit_address",
                direction: "inbound",
                status: &address.status,
                height: 0,
                tx_hash: "",
                asset_id: "xmr",
                amount: 0,
                amount_bucket: 0,
                commitment: &address.deposit_id,
                nullifier: "",
                record: address.public_record(),
            });
        }
        for observation in observations
            .iter()
            .filter(|observation| owned_deposit_ids.contains(&observation.deposit_id))
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "bridge_deposit_observation",
                direction: "inbound",
                status: &observation.status,
                height: 0,
                tx_hash: "",
                asset_id: "xmr",
                amount: observation.amount,
                amount_bucket: wallet_amount_bucket(observation.amount),
                commitment: &observation.deposit_id,
                nullifier: "",
                record: observation.public_record(),
            });
        }
        for mint in mints
            .iter()
            .filter(|mint| owned_deposit_ids.contains(&mint.deposit_id))
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "bridge_mint",
                direction: "inbound",
                status: "minted",
                height: 0,
                tx_hash: "",
                asset_id: "wxmr",
                amount: mint.amount,
                amount_bucket: wallet_amount_bucket(mint.amount),
                commitment: &mint.output_commitment,
                nullifier: "",
                record: mint.public_record(),
            });
        }
        for withdrawal in withdrawals
            .iter()
            .filter(|withdrawal| owned_withdrawal_ids.contains(&withdrawal.withdrawal_id))
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "bridge_withdrawal",
                direction: "outbound",
                status: &withdrawal.status,
                height: withdrawal.requested_at_height,
                tx_hash: &withdrawal.release_monero_txid_hash,
                asset_id: "wxmr",
                amount: withdrawal.amount,
                amount_bucket: withdrawal.amount_bucket,
                commitment: &withdrawal.withdrawal_id,
                nullifier: &withdrawal.nullifier,
                record: withdrawal.public_record(),
            });
        }
        owned_withdrawal_ids
    }

    fn ingest_monero_evidence(
        &mut self,
        owner_view_key: &str,
        watched_ids: &BTreeSet<String>,
        owned_withdrawal_ids: &BTreeSet<String>,
        sources: WalletMoneroEvidenceSources<'_>,
    ) {
        for observation in sources
            .withdrawal_observations
            .iter()
            .filter(|observation| {
                monero_withdrawal_observation_is_relevant(
                    observation,
                    watched_ids,
                    owned_withdrawal_ids,
                )
            })
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "monero_withdrawal_observation",
                direction: "outbound",
                status: &observation.status,
                height: observation.monero_block_height,
                tx_hash: &observation.txid_hash,
                asset_id: "xmr",
                amount: 0,
                amount_bucket: observation.amount_bucket,
                commitment: &observation.observation_id,
                nullifier: "",
                record: monero_withdrawal_observation_wallet_record(observation),
            });
        }

        for observation in sources
            .anchor_observations
            .iter()
            .filter(|observation| monero_anchor_observation_is_relevant(observation, watched_ids))
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "monero_anchor_observation",
                direction: "anchor",
                status: &observation.status,
                height: observation.monero_block_height,
                tx_hash: &observation.txid_hash,
                asset_id: "",
                amount: 0,
                amount_bucket: 0,
                commitment: &observation.anchor_commitment,
                nullifier: "",
                record: monero_anchor_observation_wallet_record(observation),
            });
        }

        for evidence in sources.reorg_evidence.iter().filter(|evidence| {
            monero_reorg_evidence_is_relevant(evidence, watched_ids, owned_withdrawal_ids)
        }) {
            let evidence_root = evidence.evidence_root();
            self.push_record(RecordInput {
                owner_view_key,
                kind: "monero_reorg_evidence",
                direction: "reorg",
                status: &evidence.status,
                height: evidence.reported_at_l2_height,
                tx_hash: &evidence.txid_hash,
                asset_id: "",
                amount: 0,
                amount_bucket: 0,
                commitment: &evidence_root,
                nullifier: "",
                record: monero_reorg_evidence_wallet_record(evidence),
            });
        }
    }

    fn ingest_paymaster_sponsorships(
        &mut self,
        owner_view_key: &str,
        caller_commitment: &str,
        sponsorships: &[PaymasterSponsoredCall],
    ) {
        for sponsorship in sponsorships
            .iter()
            .filter(|sponsorship| sponsorship.caller_commitment == caller_commitment)
        {
            self.push_record(RecordInput {
                owner_view_key,
                kind: "paymaster_sponsorship",
                direction: "fee_sponsored",
                status: "sponsored",
                height: sponsorship.block_height,
                tx_hash: &sponsorship.call_tx_hash,
                asset_id: &sponsorship.fee_asset_id,
                amount: sponsorship.sponsored_fee,
                amount_bucket: wallet_amount_bucket(sponsorship.sponsored_fee),
                commitment: &sponsorship.sponsorship_id,
                nullifier: "",
                record: sponsorship.public_record(),
            });
        }
    }

    fn push_record(&mut self, input: RecordInput<'_>) {
        let record_hash = domain_hash(
            "WALLET-HISTORY-RECORD",
            &[HashPart::Str(input.kind), HashPart::Json(&input.record)],
            32,
        );
        let scan_tag = wallet_scan_tag(input.owner_view_key, &record_hash);
        let history_id = domain_hash(
            "WALLET-HISTORY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(input.kind),
                HashPart::Str(&scan_tag),
                HashPart::Str(&record_hash),
            ],
            32,
        );
        self.records.push(WalletHistoryRecord {
            history_id,
            scan_tag,
            kind: input.kind.to_string(),
            direction: input.direction.to_string(),
            status: input.status.to_string(),
            height: input.height,
            tx_hash: input.tx_hash.to_string(),
            asset_id: input.asset_id.to_string(),
            amount: input.amount,
            amount_bucket: input.amount_bucket,
            commitment: input.commitment.to_string(),
            nullifier: input.nullifier.to_string(),
            record_hash,
            record: input.record,
        });
    }
}

#[derive(Clone, Debug, Default)]
pub struct WalletScanSources<'a> {
    pub notes: &'a [Note],
    pub mempool: Option<&'a MempoolState>,
    pub contract_receipts: &'a [ContractExecutionReceipt],
    pub wasm_receipts: &'a [WasmRuntimeExecutionReceipt],
    pub bridge_deposit_addresses: &'a [BridgeDepositAddress],
    pub bridge_deposit_observations: &'a [BridgeDepositObservation],
    pub bridge_mints: &'a [BridgeMintRecord],
    pub bridge_withdrawals: &'a [BridgeWithdrawalRecord],
    pub paymaster_sponsorships: &'a [PaymasterSponsoredCall],
}

impl<'a> WalletScanSources<'a> {
    pub fn with_monero_evidence(
        self,
        monero_evidence: WalletMoneroEvidenceSources<'a>,
    ) -> WalletScanSourcesWithMonero<'a> {
        WalletScanSourcesWithMonero {
            wallet_sources: self,
            monero_evidence,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct WalletScanSourcesWithMonero<'a> {
    pub wallet_sources: WalletScanSources<'a>,
    pub monero_evidence: WalletMoneroEvidenceSources<'a>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalletMoneroEvidenceSources<'a> {
    pub withdrawal_observations: &'a [MoneroWithdrawalObservation],
    pub anchor_observations: &'a [MoneroAnchorObservation],
    pub reorg_evidence: &'a [MoneroReorgEvidence],
}

struct RecordInput<'a> {
    owner_view_key: &'a str,
    kind: &'a str,
    direction: &'a str,
    status: &'a str,
    height: u64,
    tx_hash: &'a str,
    asset_id: &'a str,
    amount: u64,
    amount_bucket: u64,
    commitment: &'a str,
    nullifier: &'a str,
    record: Value,
}

pub fn wallet_owner_commitment(owner_view_key: &str) -> String {
    domain_hash("WALLET-OWNER", &[HashPart::Str(owner_view_key)], 32)
}

pub fn wallet_scan_tag(owner_view_key: &str, record_hash: &str) -> String {
    domain_hash(
        "WALLET-SCAN-TAG",
        &[HashPart::Str(owner_view_key), HashPart::Str(record_hash)],
        16,
    )
}

pub fn wallet_amount_bucket(amount: u64) -> u64 {
    if amount == 0 {
        0
    } else {
        amount.div_ceil(1_000) * 1_000
    }
}

fn monero_withdrawal_observation_is_relevant(
    observation: &MoneroWithdrawalObservation,
    watched_ids: &BTreeSet<String>,
    owned_withdrawal_ids: &BTreeSet<String>,
) -> bool {
    owned_withdrawal_ids.contains(&observation.withdrawal_id)
        || watched_ids.contains(&observation.withdrawal_id)
        || watched_ids.contains(&observation.txid_hash)
        || watched_ids.contains(&observation.observation_id)
}

fn monero_anchor_observation_is_relevant(
    observation: &MoneroAnchorObservation,
    watched_ids: &BTreeSet<String>,
) -> bool {
    watched_ids.contains(&observation.anchor_id)
        || watched_ids.contains(&observation.anchor_commitment)
        || watched_ids.contains(&observation.checkpoint_root)
        || watched_ids.contains(&observation.txid_hash)
        || watched_ids.contains(&observation.observation_id)
}

fn monero_reorg_evidence_is_relevant(
    evidence: &MoneroReorgEvidence,
    watched_ids: &BTreeSet<String>,
    owned_withdrawal_ids: &BTreeSet<String>,
) -> bool {
    watched_ids.contains(&evidence.txid_hash)
        || watched_ids.contains(&evidence.evidence_id)
        || watched_ids.contains(&evidence.evidence_root())
        || evidence
            .affected_anchor_id
            .as_deref()
            .is_some_and(|anchor_id| watched_ids.contains(anchor_id))
        || evidence
            .affected_withdrawal_id
            .as_deref()
            .is_some_and(|withdrawal_id| {
                owned_withdrawal_ids.contains(withdrawal_id) || watched_ids.contains(withdrawal_id)
            })
}

fn monero_withdrawal_observation_wallet_record(observation: &MoneroWithdrawalObservation) -> Value {
    json!({
        "kind": "monero_withdrawal_observation",
        "chain_id": CHAIN_ID,
        "observation_id": observation.observation_id,
        "withdrawal_id": observation.withdrawal_id,
        "txid_hash": observation.txid_hash,
        "amount_bucket": observation.amount_bucket,
        "recipient_address_hash": observation.recipient_address_hash,
        "monero_block_height": observation.monero_block_height,
        "monero_block_hash": observation.monero_block_hash,
        "confirmations": observation.confirmations,
        "finality_depth": observation.finality_depth,
        "status": observation.status,
        "observer_signature_root": observation.observer_signature_root,
    })
}

fn monero_anchor_observation_wallet_record(observation: &MoneroAnchorObservation) -> Value {
    json!({
        "kind": "monero_anchor_observation",
        "chain_id": CHAIN_ID,
        "observation_id": observation.observation_id,
        "anchor_id": observation.anchor_id,
        "anchor_commitment": observation.anchor_commitment,
        "checkpoint_root": observation.checkpoint_root,
        "txid_hash": observation.txid_hash,
        "monero_block_height": observation.monero_block_height,
        "monero_block_hash": observation.monero_block_hash,
        "confirmations": observation.confirmations,
        "finality_depth": observation.finality_depth,
        "status": observation.status,
        "observer_signature_root": observation.observer_signature_root,
    })
}

fn monero_reorg_evidence_wallet_record(evidence: &MoneroReorgEvidence) -> Value {
    json!({
        "kind": "monero_reorg_evidence",
        "chain_id": CHAIN_ID,
        "evidence_id": evidence.evidence_id,
        "txid_hash": evidence.txid_hash,
        "old_block_height": evidence.old_block_height,
        "old_block_hash": evidence.old_block_hash,
        "new_block_height": evidence.new_block_height,
        "new_block_hash": evidence.new_block_hash,
        "affected_anchor_id": evidence.affected_anchor_id,
        "affected_withdrawal_id": evidence.affected_withdrawal_id,
        "reported_at_l2_height": evidence.reported_at_l2_height,
        "depth": evidence.depth,
        "status": evidence.status,
        "evidence_root": evidence.evidence_root(),
        "auth_scheme": evidence.authorization.auth_scheme,
        "auth_public_key": evidence.authorization.auth_public_key,
        "auth_transcript_hash": evidence.authorization.auth_transcript_hash,
        "auth_signature": evidence.authorization.auth_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks::Validator,
        contracts::{caller_commitment, ContractCallRequest, ContractState},
        defi::{note_nullifier, DefiState},
        mempool::{
            mempool_committee_key_id, MempoolAdmission, MempoolAdmissionRequest,
            MempoolPreconfirmation,
        },
        paymasters::PaymasterSponsoredCall,
        runtime::{wasm_caller_commitment, WasmRuntimeExecutionReceipt, WASM_RUNTIME_VERSION},
        settlement::{
            BridgeDepositAddress, BridgeDepositObservation, BridgeMintRecord, BridgeSignerSet,
            BridgeWithdrawalQueueRequest, BridgeWithdrawalRecord,
        },
    };

    #[test]
    fn wallet_view_scans_owned_records_without_raw_label_leakage() {
        let owner = "alice-view-key";
        let mut defi = DefiState::new();
        let asset = defi.create_native_asset("DGR", "issuer", 10_000).unwrap();
        let minted = defi
            .submit_asset_mint(&asset.asset_id, owner, 1_250, None)
            .unwrap();
        let owned_note = minted.output_note.clone();
        let ignored_note = defi.mint(&asset.asset_id, "bob-view-key", 100).unwrap();
        let watched_nullifier = note_nullifier(&owned_note);

        let tx_public_record =
            json!({"kind": "wallet-test", "owner": wallet_owner_commitment(owner)});
        let validators = vec![Validator::new("sequencer-a", 1_000).unwrap()];
        let admission = MempoolAdmission::build(MempoolAdmissionRequest {
            tx_public_record: tx_public_record.clone(),
            tx_state_record: json!({"private": "payload"}),
            mempool_sequence: 0,
            relay_path: "tor>sequencer".to_string(),
            admitted_at_height: 3,
            expires_at_height: 6,
            sequencer_label: "sequencer-a".to_string(),
            committee_key_id: mempool_committee_key_id(&validators),
        });
        let preconfirmation =
            MempoolPreconfirmation::build(&admission, 4, "promised-root", 1, "local-fee-root")
                .unwrap();
        let mempool = MempoolState {
            pending_admissions: vec![admission.clone()],
            preconfirmations: [(preconfirmation.preconfirmation_id.clone(), preconfirmation)]
                .into_iter()
                .collect(),
            ..MempoolState::default()
        };

        let mut contracts = ContractState::new();
        let contract = contracts
            .deploy_counter_contract(owner, 100, false)
            .unwrap();
        let applied = contracts
            .execute_contract_call(ContractCallRequest::new(
                &contract.contract_id,
                "increment",
                json!({"amount": 1}),
                owner,
                20,
            ))
            .unwrap();
        assert_eq!(applied.receipt.caller_commitment, caller_commitment(owner));

        let wasm_receipt = WasmRuntimeExecutionReceipt {
            receipt_id: "wasm-receipt".to_string(),
            tx_hash: "wasm-tx".to_string(),
            contract_id: "wasm-contract".to_string(),
            module_id: "wasm-module".to_string(),
            runtime_version: WASM_RUNTIME_VERSION.to_string(),
            entrypoint: "swap".to_string(),
            args_commitment: "args".to_string(),
            private_args: true,
            caller_commitment: wasm_caller_commitment(owner),
            fuel_limit: 100,
            fuel_used: 40,
            memory_pages: 1,
            storage_root_before: "before".to_string(),
            storage_root_after: "after".to_string(),
            host_call_root: "host".to_string(),
            storage_delta_root: "delta".to_string(),
            event_root: "event".to_string(),
            fee_asset_id: asset.asset_id.clone(),
            fee: 1,
            paymaster_id: "paymaster-1".to_string(),
        };

        let signer_set = BridgeSignerSet::new(
            &["bridge-a".to_string(), "bridge-b".to_string()],
            2,
            "",
            0,
            0,
            "bridge-guardian",
        )
        .unwrap();
        let deposit_address = BridgeDepositAddress::request(owner, 0, 7, 1_700_000);
        let observation = BridgeDepositObservation::observe(
            &deposit_address,
            "monero-tx",
            2_500,
            10,
            &signer_set,
            &signer_set.signer_labels,
        )
        .unwrap();
        let mint = BridgeMintRecord::from_observation(&observation, owned_note.commitment.clone());
        let withdrawal = BridgeWithdrawalRecord::queue(
            BridgeWithdrawalQueueRequest {
                spent_note_id: owned_note.note_id.clone(),
                nullifier: watched_nullifier.clone(),
                amount: 1_000,
                monero_address: "xmr-destination".to_string(),
                bridge_fee: 1,
                requested_at_height: 8,
            },
            &signer_set,
            &signer_set.signer_labels,
        )
        .unwrap();
        let sponsorship = PaymasterSponsoredCall {
            sponsorship_id: "sponsorship-1".to_string(),
            paymaster_id: "paymaster-1".to_string(),
            call_tx_hash: applied.call.args_commitment(),
            contract_id: contract.contract_id.clone(),
            caller_commitment: paymaster_caller_commitment(owner),
            fee_asset_id: asset.asset_id.clone(),
            sponsored_fee: 1,
            balance_before: 3,
            balance_after: 2,
            spent_by_caller_before: 0,
            spent_by_caller_after: 1,
            policy_hash: "policy".to_string(),
            call_public_record_hash: "call-record".to_string(),
            block_height: 5,
        };

        let notes = vec![owned_note, ignored_note];
        let sources = WalletScanSources {
            notes: &notes,
            mempool: Some(&mempool),
            contract_receipts: std::slice::from_ref(&applied.receipt),
            wasm_receipts: std::slice::from_ref(&wasm_receipt),
            bridge_deposit_addresses: std::slice::from_ref(&deposit_address),
            bridge_deposit_observations: std::slice::from_ref(&observation),
            bridge_mints: std::slice::from_ref(&mint),
            bridge_withdrawals: std::slice::from_ref(&withdrawal),
            paymaster_sponsorships: std::slice::from_ref(&sponsorship),
        };
        let view = WalletSyncIndex::new()
            .scan(
                WalletScanRequest::new(owner, 12)
                    .watch_tx_hash(admission.tx_public_hash.clone())
                    .watch_nullifier(watched_nullifier),
                sources,
            )
            .unwrap();

        let kinds = view
            .records
            .iter()
            .map(|record| record.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(view.records.len(), 10);
        assert!(kinds.contains("note"));
        assert!(kinds.contains("mempool_admission"));
        assert!(kinds.contains("mempool_preconfirmation"));
        assert!(kinds.contains("contract_receipt"));
        assert!(kinds.contains("wasm_receipt"));
        assert!(kinds.contains("bridge_deposit_address"));
        assert!(kinds.contains("bridge_deposit_observation"));
        assert!(kinds.contains("bridge_mint"));
        assert!(kinds.contains("bridge_withdrawal"));
        assert!(kinds.contains("paymaster_sponsorship"));
        assert_eq!(view.history_root().len(), 64);
        let public = view.public_record().to_string();
        assert!(!public.contains(owner));
        assert!(!public.contains("bob-view-key"));
        assert!(!public.contains("tor>sequencer"));
        assert!(!public.contains("xmr-destination"));
    }
}
