use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "monero-l2-pq-private-bridge-execution-settlement-coordinator/v1";
pub const PQ_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f";
pub const MANIFEST_ENCRYPTION: &str = "hpke-ml-kem-1024-aes256gcm";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub min_monero_confirmations: u64,
    pub reorg_guard_depth: u64,
    pub watcher_quorum: u32,
    pub reserve_quorum: u32,
    pub max_fast_exit_fee_atomic_units: u64,
    pub sponsor_rebate_bps: u32,
    pub max_manifest_items: usize,
    pub privacy_epoch: u64,
    pub pq_scheme: String,
    pub manifest_encryption: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub next_sequence: u64,
    pub bridge_outputs: u64,
    pub subaddress_claims: u64,
    pub execution_receipts: u64,
    pub reserve_proofs: u64,
    pub fast_exits: u64,
    pub reorg_guards: u64,
    pub watcher_attestations: u64,
    pub manifests: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub slashing_evidence: u64,
    pub settled_manifests: u64,
    pub rejected_records: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub bridge_output_root: String,
    pub subaddress_claim_root: String,
    pub execution_receipt_root: String,
    pub reserve_proof_root: String,
    pub fast_exit_root: String,
    pub reorg_guard_root: String,
    pub watcher_attestation_root: String,
    pub manifest_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub slashing_evidence_root: String,
    pub convergence_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqAuthorization {
    pub scheme: String,
    pub public_key_commitment: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoneroBridgeOutput {
    pub output_id: String,
    pub txid: String,
    pub output_index: u32,
    pub subaddress_id: String,
    pub one_time_public_key: String,
    pub view_tag: String,
    pub amount_commitment: String,
    pub encrypted_amount: String,
    pub decoy_set_root: String,
    pub key_image_commitment: String,
    pub note_commitment: String,
    pub observed_height: u64,
    pub unlock_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubaddressClaim {
    pub claim_id: String,
    pub output_id: String,
    pub subaddress_id: String,
    pub claimant_commitment: String,
    pub spend_authority_commitment: String,
    pub view_key_audit_tag: String,
    pub claim_nullifier: String,
    pub pq_authorization: PqAuthorization,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateExecutionReceipt {
    pub receipt_id: String,
    pub claim_id: String,
    pub contract_id: String,
    pub call_commitment: String,
    pub private_input_root: String,
    pub private_output_root: String,
    pub token_delta_root: String,
    pub fee_commitment: String,
    pub proof_commitment: String,
    pub receipt_nullifier: String,
    pub gas_used: u64,
    pub status: ReceiptStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptStatus {
    Proven,
    Settled,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeReserveProof {
    pub proof_id: String,
    pub reserve_epoch: u64,
    pub custodian_set_root: String,
    pub view_key_disclosure_root: String,
    pub liability_root: String,
    pub asset_root: String,
    pub total_reserve_commitment: String,
    pub required_liability_commitment: String,
    pub watcher_votes: BTreeSet<String>,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FastLiquidityExit {
    pub exit_id: String,
    pub receipt_id: String,
    pub output_id: String,
    pub liquidity_provider: String,
    pub exit_amount_commitment: String,
    pub fee_quote_atomic_units: u64,
    pub provider_bond_commitment: String,
    pub private_destination_commitment: String,
    pub sponsor_id: Option<String>,
    pub status: ExitStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExitStatus {
    Filled,
    Manifested,
    Settled,
    Disputed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReorgGuard {
    pub guard_id: String,
    pub output_id: String,
    pub monero_height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub anchor_root: String,
    pub depth: u64,
    pub risk_score: u32,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub observed_root: String,
    pub vote: AttestationVote,
    pub pq_signature: PqAuthorization,
    pub evidence_hash: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationVote {
    Accept,
    Reject,
    Challenge,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedSettlementManifest {
    pub manifest_id: String,
    pub epoch: u64,
    pub reserve_proof_id: String,
    pub ciphertext_hash: String,
    pub item_root: String,
    pub included_receipts: BTreeSet<String>,
    pub included_exits: BTreeSet<String>,
    pub encrypted_key_commitment: String,
    pub settlement_anchor: String,
    pub status: ManifestStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManifestStatus {
    Draft,
    Attested,
    Settled,
    Challenged,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeSponsorRebate {
    pub rebate_id: String,
    pub sponsor_id: String,
    pub receipt_id: String,
    pub exit_id: Option<String>,
    pub gas_fee_commitment: String,
    pub rebate_commitment: String,
    pub eligibility_root: String,
    pub nullifier: String,
    pub paid: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub epoch: u64,
    pub domain: String,
    pub source_id: String,
    pub commitment: String,
    pub nullifier: String,
    pub policy_root: String,
    pub consumed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub offender_id: String,
    pub subject_id: String,
    pub offense: SlashingOffense,
    pub evidence_root: String,
    pub conflicting_roots: BTreeSet<String>,
    pub reporter_id: String,
    pub penalty_commitment: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingOffense {
    DoubleAttestation,
    InvalidReserveProof,
    ReorgConcealment,
    LiquidityDefault,
    PrivacyFenceViolation,
    ManifestEquivocation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub bridge_outputs: BTreeMap<String, MoneroBridgeOutput>,
    pub subaddress_claims: BTreeMap<String, SubaddressClaim>,
    pub execution_receipts: BTreeMap<String, PrivateExecutionReceipt>,
    pub reserve_proofs: BTreeMap<String, BridgeReserveProof>,
    pub fast_exits: BTreeMap<String, FastLiquidityExit>,
    pub reorg_guards: BTreeMap<String, ReorgGuard>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub manifests: BTreeMap<String, EncryptedSettlementManifest>,
    pub rebates: BTreeMap<String, FeeSponsorRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub nullifiers: BTreeSet<String>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub watcher_index: BTreeMap<String, BTreeSet<String>>,
    pub receipt_by_claim: BTreeMap<String, BTreeSet<String>>,
    pub exits_by_receipt: BTreeMap<String, BTreeSet<String>>,
    pub manifest_by_receipt: BTreeMap<String, String>,
    pub event_log: Vec<String>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            min_monero_confirmations: 18,
            reorg_guard_depth: 24,
            watcher_quorum: 3,
            reserve_quorum: 3,
            max_fast_exit_fee_atomic_units: 40_000,
            sponsor_rebate_bps: 7_000,
            max_manifest_items: 512,
            privacy_epoch: 1,
            pq_scheme: PQ_SCHEME.to_string(),
            manifest_encryption: MANIFEST_ENCRYPTION.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            next_sequence: 1,
            bridge_outputs: 0,
            subaddress_claims: 0,
            execution_receipts: 0,
            reserve_proofs: 0,
            fast_exits: 0,
            reorg_guards: 0,
            watcher_attestations: 0,
            manifests: 0,
            rebates: 0,
            privacy_fences: 0,
            slashing_evidence: 0,
            settled_manifests: 0,
            rejected_records: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Roots {
    pub fn empty() -> Self {
        let mut roots = Self {
            bridge_output_root: empty_root("BRIDGE-OUTPUT"),
            subaddress_claim_root: empty_root("SUBADDRESS-CLAIM"),
            execution_receipt_root: empty_root("EXECUTION-RECEIPT"),
            reserve_proof_root: empty_root("RESERVE-PROOF"),
            fast_exit_root: empty_root("FAST-EXIT"),
            reorg_guard_root: empty_root("REORG-GUARD"),
            watcher_attestation_root: empty_root("WATCHER-ATTESTATION"),
            manifest_root: empty_root("MANIFEST"),
            rebate_root: empty_root("REBATE"),
            privacy_fence_root: empty_root("PRIVACY-FENCE"),
            nullifier_root: empty_root("NULLIFIER"),
            slashing_evidence_root: empty_root("SLASHING-EVIDENCE"),
            convergence_root: empty_root("CONVERGENCE"),
            state_root: empty_root("STATE"),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn compute_state_root(&self) -> String {
        hash_json(
            "STATE-ROOT",
            &json!({
                "bridge_output_root": self.bridge_output_root,
                "convergence_root": self.convergence_root,
                "execution_receipt_root": self.execution_receipt_root,
                "fast_exit_root": self.fast_exit_root,
                "manifest_root": self.manifest_root,
                "nullifier_root": self.nullifier_root,
                "privacy_fence_root": self.privacy_fence_root,
                "rebate_root": self.rebate_root,
                "reorg_guard_root": self.reorg_guard_root,
                "reserve_proof_root": self.reserve_proof_root,
                "slashing_evidence_root": self.slashing_evidence_root,
                "subaddress_claim_root": self.subaddress_claim_root,
                "watcher_attestation_root": self.watcher_attestation_root
            }),
        )
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::empty(),
            roots: Roots::empty(),
            bridge_outputs: BTreeMap::new(),
            subaddress_claims: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            fast_exits: BTreeMap::new(),
            reorg_guards: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            manifests: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            slashing_evidence: BTreeMap::new(),
            watcher_index: BTreeMap::new(),
            receipt_by_claim: BTreeMap::new(),
            exits_by_receipt: BTreeMap::new(),
            manifest_by_receipt: BTreeMap::new(),
            event_log: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "event_root": string_root("EVENT", self.event_log.iter()),
            "protocol_version": PROTOCOL_VERSION,
            "roots": self.roots.public_record()
        })
    }

    pub fn register_bridge_output(
        &mut self,
        txid: &str,
        output_index: u32,
        subaddress_id: &str,
        one_time_public_key: &str,
        amount_commitment: &str,
        encrypted_amount: &str,
        observed_height: u64,
        unlock_height: u64,
    ) -> Result<String> {
        require_nonempty("txid", txid)?;
        require_nonempty("subaddress_id", subaddress_id)?;
        require_nonempty("one_time_public_key", one_time_public_key)?;
        let output_id = bridge_output_id(txid, output_index, one_time_public_key);
        if self.bridge_outputs.contains_key(&output_id) {
            return Err(format!("bridge output already registered: {output_id}"));
        }
        let output = MoneroBridgeOutput {
            output_id: output_id.clone(),
            txid: txid.to_string(),
            output_index,
            subaddress_id: subaddress_id.to_string(),
            one_time_public_key: one_time_public_key.to_string(),
            view_tag: view_tag_id(one_time_public_key, subaddress_id),
            amount_commitment: amount_commitment.to_string(),
            encrypted_amount: encrypted_amount.to_string(),
            decoy_set_root: deterministic_id("DECOY-SET", &[txid, &output_index.to_string()]),
            key_image_commitment: commitment_id("KEY-IMAGE", &[txid, one_time_public_key]),
            note_commitment: commitment_id("NOTE", &[txid, amount_commitment, subaddress_id]),
            observed_height,
            unlock_height,
        };
        self.bridge_outputs.insert(output_id.clone(), output);
        self.counters.bridge_outputs += 1;
        self.push_event("bridge_output", &output_id);
        self.recompute_roots();
        Ok(output_id)
    }

    pub fn claim_subaddress(
        &mut self,
        output_id: &str,
        claimant_commitment: &str,
        spend_authority_commitment: &str,
        view_key_audit_tag: &str,
        pq_authorization: PqAuthorization,
    ) -> Result<String> {
        self.require_pq_authorization(&pq_authorization)?;
        let output = self
            .bridge_outputs
            .get(output_id)
            .ok_or_else(|| format!("unknown bridge output: {output_id}"))?;
        let subaddress_id = output.subaddress_id.clone();
        let claim_nullifier = nullifier_id("SUBADDRESS-CLAIM", &[output_id, claimant_commitment]);
        self.insert_nullifier(&claim_nullifier)?;
        let claim_id = deterministic_id(
            "SUBADDRESS-CLAIM-ID",
            &[output_id, claimant_commitment, spend_authority_commitment],
        );
        let claim = SubaddressClaim {
            claim_id: claim_id.clone(),
            output_id: output_id.to_string(),
            subaddress_id,
            claimant_commitment: claimant_commitment.to_string(),
            spend_authority_commitment: spend_authority_commitment.to_string(),
            view_key_audit_tag: view_key_audit_tag.to_string(),
            claim_nullifier,
            pq_authorization,
            accepted: true,
        };
        self.subaddress_claims.insert(claim_id.clone(), claim);
        self.counters.subaddress_claims += 1;
        self.push_event("subaddress_claim", &claim_id);
        self.recompute_roots();
        Ok(claim_id)
    }

    pub fn record_execution_receipt(
        &mut self,
        claim_id: &str,
        contract_id: &str,
        call_commitment: &str,
        private_input_root: &str,
        private_output_root: &str,
        token_delta_root: &str,
        gas_used: u64,
        proof_commitment: &str,
    ) -> Result<String> {
        if !self.subaddress_claims.contains_key(claim_id) {
            return Err(format!("unknown subaddress claim: {claim_id}"));
        }
        let receipt_nullifier =
            nullifier_id("EXECUTION", &[claim_id, contract_id, call_commitment]);
        self.insert_nullifier(&receipt_nullifier)?;
        let receipt_id = deterministic_id(
            "EXECUTION-RECEIPT-ID",
            &[claim_id, contract_id, &receipt_nullifier],
        );
        let receipt = PrivateExecutionReceipt {
            receipt_id: receipt_id.clone(),
            claim_id: claim_id.to_string(),
            contract_id: contract_id.to_string(),
            call_commitment: call_commitment.to_string(),
            private_input_root: private_input_root.to_string(),
            private_output_root: private_output_root.to_string(),
            token_delta_root: token_delta_root.to_string(),
            fee_commitment: commitment_id("FEE", &[claim_id, &gas_used.to_string()]),
            proof_commitment: proof_commitment.to_string(),
            receipt_nullifier,
            gas_used,
            status: ReceiptStatus::Proven,
        };
        self.execution_receipts.insert(receipt_id.clone(), receipt);
        self.receipt_by_claim
            .entry(claim_id.to_string())
            .or_default()
            .insert(receipt_id.clone());
        self.counters.execution_receipts += 1;
        self.push_event("execution_receipt", &receipt_id);
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn submit_reserve_proof(
        &mut self,
        reserve_epoch: u64,
        custodian_set_root: &str,
        view_key_disclosure_root: &str,
        liability_root: &str,
        asset_root: &str,
        total_reserve_commitment: &str,
        required_liability_commitment: &str,
    ) -> Result<String> {
        require_nonempty("custodian_set_root", custodian_set_root)?;
        let proof_id = deterministic_id(
            "RESERVE-PROOF-ID",
            &[
                &reserve_epoch.to_string(),
                custodian_set_root,
                liability_root,
                asset_root,
            ],
        );
        let proof = BridgeReserveProof {
            proof_id: proof_id.clone(),
            reserve_epoch,
            custodian_set_root: custodian_set_root.to_string(),
            view_key_disclosure_root: view_key_disclosure_root.to_string(),
            liability_root: liability_root.to_string(),
            asset_root: asset_root.to_string(),
            total_reserve_commitment: total_reserve_commitment.to_string(),
            required_liability_commitment: required_liability_commitment.to_string(),
            watcher_votes: BTreeSet::new(),
            accepted: false,
        };
        self.reserve_proofs.insert(proof_id.clone(), proof);
        self.counters.reserve_proofs += 1;
        self.push_event("reserve_proof", &proof_id);
        self.recompute_roots();
        Ok(proof_id)
    }

    pub fn open_fast_exit(
        &mut self,
        receipt_id: &str,
        output_id: &str,
        liquidity_provider: &str,
        exit_amount_commitment: &str,
        fee_quote_atomic_units: u64,
        private_destination_commitment: &str,
        sponsor_id: Option<String>,
    ) -> Result<String> {
        if !self.execution_receipts.contains_key(receipt_id) {
            return Err(format!("unknown execution receipt: {receipt_id}"));
        }
        if !self.bridge_outputs.contains_key(output_id) {
            return Err(format!("unknown bridge output: {output_id}"));
        }
        if fee_quote_atomic_units > self.config.max_fast_exit_fee_atomic_units {
            return Err(format!("fast exit fee too high: {fee_quote_atomic_units}"));
        }
        let provider_bond_commitment = commitment_id(
            "PROVIDER-BOND",
            &[receipt_id, output_id, liquidity_provider],
        );
        let exit_id = deterministic_id(
            "FAST-EXIT-ID",
            &[
                receipt_id,
                output_id,
                liquidity_provider,
                &provider_bond_commitment,
            ],
        );
        let exit = FastLiquidityExit {
            exit_id: exit_id.clone(),
            receipt_id: receipt_id.to_string(),
            output_id: output_id.to_string(),
            liquidity_provider: liquidity_provider.to_string(),
            exit_amount_commitment: exit_amount_commitment.to_string(),
            fee_quote_atomic_units,
            provider_bond_commitment,
            private_destination_commitment: private_destination_commitment.to_string(),
            sponsor_id,
            status: ExitStatus::Filled,
        };
        self.fast_exits.insert(exit_id.clone(), exit);
        self.exits_by_receipt
            .entry(receipt_id.to_string())
            .or_default()
            .insert(exit_id.clone());
        self.counters.fast_exits += 1;
        self.push_event("fast_exit", &exit_id);
        self.recompute_roots();
        Ok(exit_id)
    }

    pub fn install_reorg_guard(
        &mut self,
        output_id: &str,
        monero_height: u64,
        block_hash: &str,
        parent_hash: &str,
        risk_score: u32,
    ) -> Result<String> {
        if !self.bridge_outputs.contains_key(output_id) {
            return Err(format!("unknown bridge output: {output_id}"));
        }
        let guard_id = deterministic_id(
            "REORG-GUARD-ID",
            &[output_id, &monero_height.to_string(), block_hash],
        );
        let anchor_root = hash_json(
            "REORG-ANCHOR",
            &json!({"block_hash": block_hash, "height": monero_height, "parent_hash": parent_hash}),
        );
        self.reorg_guards.insert(
            guard_id.clone(),
            ReorgGuard {
                guard_id: guard_id.clone(),
                output_id: output_id.to_string(),
                monero_height,
                block_hash: block_hash.to_string(),
                parent_hash: parent_hash.to_string(),
                anchor_root,
                depth: self.config.reorg_guard_depth,
                risk_score,
                active: true,
            },
        );
        self.counters.reorg_guards += 1;
        self.push_event("reorg_guard", &guard_id);
        self.recompute_roots();
        Ok(guard_id)
    }

    pub fn attest(
        &mut self,
        watcher_id: &str,
        subject_kind: &str,
        subject_id: &str,
        vote: AttestationVote,
        observed_root: &str,
        pq_signature: PqAuthorization,
        height: u64,
    ) -> Result<String> {
        self.require_subject(subject_kind, subject_id)?;
        self.require_pq_authorization(&pq_signature)?;
        let attestation_id = deterministic_id(
            "WATCHER-ATTESTATION-ID",
            &[watcher_id, subject_kind, subject_id, &height.to_string()],
        );
        let attestation = WatcherAttestation {
            attestation_id: attestation_id.clone(),
            watcher_id: watcher_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            observed_root: observed_root.to_string(),
            vote: vote.clone(),
            pq_signature,
            evidence_hash: deterministic_id(
                "WATCHER-EVIDENCE",
                &[watcher_id, subject_kind, subject_id, observed_root],
            ),
            height,
        };
        self.watcher_attestations
            .insert(attestation_id.clone(), attestation);
        self.watcher_index
            .entry(subject_id.to_string())
            .or_default()
            .insert(attestation_id.clone());
        if subject_kind == "reserve_proof" && vote == AttestationVote::Accept {
            if let Some(proof) = self.reserve_proofs.get_mut(subject_id) {
                proof.watcher_votes.insert(watcher_id.to_string());
                proof.accepted = proof.watcher_votes.len() >= self.config.reserve_quorum as usize;
            }
        }
        self.counters.watcher_attestations += 1;
        self.push_event("watcher_attestation", &attestation_id);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn build_encrypted_manifest(
        &mut self,
        reserve_proof_id: &str,
        receipt_ids: BTreeSet<String>,
        exit_ids: BTreeSet<String>,
        encrypted_key_commitment: &str,
    ) -> Result<String> {
        let proof = self
            .reserve_proofs
            .get(reserve_proof_id)
            .ok_or_else(|| format!("unknown reserve proof: {reserve_proof_id}"))?;
        if !proof.accepted {
            return Err(format!("reserve proof lacks quorum: {reserve_proof_id}"));
        }
        if receipt_ids.len() + exit_ids.len() > self.config.max_manifest_items {
            return Err("manifest item limit exceeded".to_string());
        }
        for receipt_id in &receipt_ids {
            if !self.execution_receipts.contains_key(receipt_id) {
                return Err(format!("unknown receipt: {receipt_id}"));
            }
        }
        for exit_id in &exit_ids {
            if !self.fast_exits.contains_key(exit_id) {
                return Err(format!("unknown fast exit: {exit_id}"));
            }
        }
        let item_root = manifest_item_root(&receipt_ids, &exit_ids);
        let ciphertext_hash =
            deterministic_id("MANIFEST-CIPHERTEXT", &[reserve_proof_id, &item_root]);
        let manifest_id = deterministic_id(
            "MANIFEST-ID",
            &[reserve_proof_id, &item_root, &ciphertext_hash],
        );
        let manifest = EncryptedSettlementManifest {
            manifest_id: manifest_id.clone(),
            epoch: proof.reserve_epoch,
            reserve_proof_id: reserve_proof_id.to_string(),
            ciphertext_hash: ciphertext_hash.clone(),
            item_root,
            included_receipts: receipt_ids.clone(),
            included_exits: exit_ids.clone(),
            encrypted_key_commitment: encrypted_key_commitment.to_string(),
            settlement_anchor: hash_json(
                "SETTLEMENT-ANCHOR",
                &json!({"ciphertext_hash": ciphertext_hash, "manifest_id": manifest_id}),
            ),
            status: ManifestStatus::Draft,
        };
        for receipt_id in receipt_ids {
            self.manifest_by_receipt
                .insert(receipt_id, manifest_id.clone());
        }
        for exit_id in exit_ids {
            if let Some(exit) = self.fast_exits.get_mut(&exit_id) {
                exit.status = ExitStatus::Manifested;
            }
        }
        self.manifests.insert(manifest_id.clone(), manifest);
        self.counters.manifests += 1;
        self.push_event("manifest", &manifest_id);
        self.recompute_roots();
        Ok(manifest_id)
    }

    pub fn mark_manifest_attested(&mut self, manifest_id: &str) -> Result<()> {
        let votes = self
            .watcher_index
            .get(manifest_id)
            .map(BTreeSet::len)
            .unwrap_or(0);
        if votes < self.config.watcher_quorum as usize {
            return Err(format!("manifest lacks watcher quorum: {manifest_id}"));
        }
        self.manifests
            .get_mut(manifest_id)
            .ok_or_else(|| format!("unknown manifest: {manifest_id}"))?
            .status = ManifestStatus::Attested;
        self.push_event("manifest_attested", manifest_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn settle_manifest(&mut self, manifest_id: &str) -> Result<()> {
        let manifest = self
            .manifests
            .get_mut(manifest_id)
            .ok_or_else(|| format!("unknown manifest: {manifest_id}"))?;
        if manifest.status != ManifestStatus::Attested {
            return Err(format!("manifest is not attested: {manifest_id}"));
        }
        manifest.status = ManifestStatus::Settled;
        for receipt_id in manifest.included_receipts.clone() {
            if let Some(receipt) = self.execution_receipts.get_mut(&receipt_id) {
                receipt.status = ReceiptStatus::Settled;
            }
        }
        for exit_id in manifest.included_exits.clone() {
            if let Some(exit) = self.fast_exits.get_mut(&exit_id) {
                exit.status = ExitStatus::Settled;
            }
        }
        self.counters.settled_manifests += 1;
        self.push_event("manifest_settled", manifest_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn issue_fee_sponsor_rebate(
        &mut self,
        sponsor_id: &str,
        receipt_id: &str,
        exit_id: Option<String>,
        gas_fee_commitment: &str,
        eligibility_root: &str,
    ) -> Result<String> {
        if !self.execution_receipts.contains_key(receipt_id) {
            return Err(format!("unknown receipt: {receipt_id}"));
        }
        let nullifier = nullifier_id("REBATE", &[sponsor_id, receipt_id]);
        self.insert_nullifier(&nullifier)?;
        let rebate_id = deterministic_id("REBATE-ID", &[sponsor_id, receipt_id, &nullifier]);
        self.rebates.insert(
            rebate_id.clone(),
            FeeSponsorRebate {
                rebate_id: rebate_id.clone(),
                sponsor_id: sponsor_id.to_string(),
                receipt_id: receipt_id.to_string(),
                exit_id,
                gas_fee_commitment: gas_fee_commitment.to_string(),
                rebate_commitment: commitment_id("REBATE", &[sponsor_id, receipt_id]),
                eligibility_root: eligibility_root.to_string(),
                nullifier,
                paid: true,
            },
        );
        self.counters.rebates += 1;
        self.push_event("rebate", &rebate_id);
        self.recompute_roots();
        Ok(rebate_id)
    }

    pub fn add_privacy_fence(
        &mut self,
        domain: &str,
        source_id: &str,
        commitment: &str,
        policy_root: &str,
    ) -> Result<String> {
        let nullifier = nullifier_id(domain, &[source_id, commitment]);
        self.insert_nullifier(&nullifier)?;
        let fence_id = deterministic_id("PRIVACY-FENCE-ID", &[domain, source_id, &nullifier]);
        self.privacy_fences.insert(
            fence_id.clone(),
            PrivacyFence {
                fence_id: fence_id.clone(),
                epoch: self.config.privacy_epoch,
                domain: domain.to_string(),
                source_id: source_id.to_string(),
                commitment: commitment.to_string(),
                nullifier,
                policy_root: policy_root.to_string(),
                consumed: true,
            },
        );
        self.counters.privacy_fences += 1;
        self.push_event("privacy_fence", &fence_id);
        self.recompute_roots();
        Ok(fence_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        offender_id: &str,
        subject_id: &str,
        offense: SlashingOffense,
        conflicting_roots: BTreeSet<String>,
        reporter_id: &str,
    ) -> Result<String> {
        if conflicting_roots.len() < 2 {
            return Err("slashing evidence requires at least two conflicting roots".to_string());
        }
        let evidence_root = set_root("SLASHING-CONFLICT", &conflicting_roots);
        let evidence_id = deterministic_id(
            "SLASHING-EVIDENCE-ID",
            &[offender_id, subject_id, &evidence_root, reporter_id],
        );
        self.slashing_evidence.insert(
            evidence_id.clone(),
            SlashingEvidence {
                evidence_id: evidence_id.clone(),
                offender_id: offender_id.to_string(),
                subject_id: subject_id.to_string(),
                offense,
                evidence_root: evidence_root.clone(),
                conflicting_roots,
                reporter_id: reporter_id.to_string(),
                penalty_commitment: commitment_id(
                    "SLASHING-PENALTY",
                    &[offender_id, &evidence_root],
                ),
                accepted: true,
            },
        );
        self.counters.slashing_evidence += 1;
        self.push_event("slashing_evidence", &evidence_id);
        self.recompute_roots();
        Ok(evidence_id)
    }

    pub fn recompute_roots(&mut self) {
        self.roots.bridge_output_root = map_root("BRIDGE-OUTPUT", &self.bridge_outputs);
        self.roots.subaddress_claim_root = map_root("SUBADDRESS-CLAIM", &self.subaddress_claims);
        self.roots.execution_receipt_root = map_root("EXECUTION-RECEIPT", &self.execution_receipts);
        self.roots.reserve_proof_root = map_root("RESERVE-PROOF", &self.reserve_proofs);
        self.roots.fast_exit_root = map_root("FAST-EXIT", &self.fast_exits);
        self.roots.reorg_guard_root = map_root("REORG-GUARD", &self.reorg_guards);
        self.roots.watcher_attestation_root =
            map_root("WATCHER-ATTESTATION", &self.watcher_attestations);
        self.roots.manifest_root = map_root("MANIFEST", &self.manifests);
        self.roots.rebate_root = map_root("REBATE", &self.rebates);
        self.roots.privacy_fence_root = map_root("PRIVACY-FENCE", &self.privacy_fences);
        self.roots.nullifier_root = set_root("NULLIFIER", &self.nullifiers);
        self.roots.slashing_evidence_root = map_root("SLASHING-EVIDENCE", &self.slashing_evidence);
        self.roots.convergence_root = hash_json(
            "CONVERGENCE",
            &json!({
                "bridge": self.roots.bridge_output_root,
                "execution": self.roots.execution_receipt_root,
                "manifest": self.roots.manifest_root,
                "reserve": self.roots.reserve_proof_root,
                "watchers": self.roots.watcher_attestation_root
            }),
        );
        self.roots.state_root = self.roots.compute_state_root();
    }

    fn insert_nullifier(&mut self, nullifier: &str) -> Result<()> {
        if self.nullifiers.contains(nullifier) {
            self.counters.rejected_records += 1;
            return Err(format!("duplicate nullifier: {nullifier}"));
        }
        self.nullifiers.insert(nullifier.to_string());
        Ok(())
    }

    fn require_pq_authorization(&self, auth: &PqAuthorization) -> Result<()> {
        if auth.scheme != self.config.pq_scheme {
            return Err(format!("unsupported pq scheme: {}", auth.scheme));
        }
        require_nonempty("public_key_commitment", &auth.public_key_commitment)?;
        require_nonempty("transcript_hash", &auth.transcript_hash)?;
        require_nonempty("signature_commitment", &auth.signature_commitment)
    }

    fn require_subject(&self, subject_kind: &str, subject_id: &str) -> Result<()> {
        let exists = match subject_kind {
            "bridge_output" => self.bridge_outputs.contains_key(subject_id),
            "subaddress_claim" => self.subaddress_claims.contains_key(subject_id),
            "execution_receipt" => self.execution_receipts.contains_key(subject_id),
            "reserve_proof" => self.reserve_proofs.contains_key(subject_id),
            "fast_exit" => self.fast_exits.contains_key(subject_id),
            "reorg_guard" => self.reorg_guards.contains_key(subject_id),
            "manifest" => self.manifests.contains_key(subject_id),
            _ => false,
        };
        if exists {
            Ok(())
        } else {
            Err(format!("unknown {subject_kind} subject: {subject_id}"))
        }
    }

    fn push_event(&mut self, kind: &str, id: &str) {
        let event = deterministic_id(
            "EVENT",
            &[
                kind,
                id,
                &self.counters.next_sequence.to_string(),
                &self.roots.state_root,
            ],
        );
        self.counters.next_sequence += 1;
        self.event_log.push(event);
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

macro_rules! impl_public_record_json {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl PublicRecord for $ty {
                fn public_record(&self) -> Value {
                    json!(self)
                }
            }
        )+
    };
}

impl_public_record_json!(
    MoneroBridgeOutput,
    SubaddressClaim,
    PrivateExecutionReceipt,
    BridgeReserveProof,
    FastLiquidityExit,
    ReorgGuard,
    WatcherAttestation,
    EncryptedSettlementManifest,
    FeeSponsorRebate,
    PrivacyFence,
    SlashingEvidence,
);

impl PqAuthorization {
    pub fn new(label: &str, public_key_commitment: &str, signature_commitment: &str) -> Self {
        Self {
            scheme: PQ_SCHEME.to_string(),
            public_key_commitment: public_key_commitment.to_string(),
            transcript_hash: deterministic_id(
                "PQ-AUTH-TRANSCRIPT",
                &[label, public_key_commitment, signature_commitment],
            ),
            signature_commitment: signature_commitment.to_string(),
        }
    }
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

pub fn hash_json(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn bridge_output_id(txid: &str, output_index: u32, one_time_public_key: &str) -> String {
    deterministic_id(
        "MONERO-BRIDGE-OUTPUT-ID",
        &[txid, &output_index.to_string(), one_time_public_key],
    )
}

pub fn view_tag_id(one_time_public_key: &str, subaddress_id: &str) -> String {
    deterministic_id("MONERO-VIEW-TAG", &[one_time_public_key, subaddress_id])
}

pub fn nullifier_id(domain: &str, parts: &[&str]) -> String {
    deterministic_id(
        &format!("NULLIFIER-{domain}"),
        &[CHAIN_ID, &parts.join(":")],
    )
}

pub fn commitment_id(domain: &str, parts: &[&str]) -> String {
    deterministic_id(
        &format!("COMMITMENT-{domain}"),
        &[CHAIN_ID, &parts.join(":")],
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(&format!("MONERO-L2-PQ-PRIVATE-{domain}"), &[])
}

pub fn map_root<T: PublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(id, item)| json!({"id": id, "record": item.public_record()}))
        .collect::<Vec<_>>();
    merkle_root(&format!("MONERO-L2-PQ-PRIVATE-{domain}"), &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|item| json!({"item": item}))
        .collect::<Vec<_>>();
    merkle_root(&format!("MONERO-L2-PQ-PRIVATE-{domain}"), &leaves)
}

pub fn string_root<'a, I>(domain: &str, values: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = values
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(&format!("MONERO-L2-PQ-PRIVATE-{domain}"), &leaves)
}

pub fn manifest_item_root(receipt_ids: &BTreeSet<String>, exit_ids: &BTreeSet<String>) -> String {
    hash_json(
        "MANIFEST-ITEM-ROOT",
        &json!({
            "exit_root": set_root("MANIFEST-EXIT", exit_ids),
            "receipt_root": set_root("MANIFEST-RECEIPT", receipt_ids)
        }),
    )
}

pub fn watcher_subject_root(subject_kind: &str, subject_id: &str, observed_root: &str) -> String {
    hash_json(
        "WATCHER-SUBJECT-ROOT",
        &json!({
            "observed_root": observed_root,
            "subject_id": subject_id,
            "subject_kind": subject_kind
        }),
    )
}

pub fn reserve_balance_root(asset_roots: &BTreeMap<String, String>) -> String {
    let leaves = asset_roots
        .iter()
        .map(|(asset, root)| json!({"asset": asset, "root": root}))
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-PRIVATE-RESERVE-BALANCE", &leaves)
}

pub fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
