use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    crypto_policy::{
        account_record, crypto_policy_root, sign_prover_authorization,
        sign_validator_authorization, verify_prover_authorization, verify_validator_authorization,
        Authorization, CryptoRole,
    },
    fees::{execution_profile_from_resources, BlockExecutionProfile, FeeMarketResource},
    hash::{canonical_json_string, domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const DEVNET_DA_SHARD_SIZE: usize = 512;

pub type BlockResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub validator_id: String,
    pub label: String,
    pub stake: u64,
    pub consensus_public_key: String,
    pub network_public_key: String,
    pub status: String,
    pub slashed_stake: u64,
    pub omission_count: u64,
    pub preconfirmation_miss_count: u64,
    pub block_challenge_count: u64,
}

impl Validator {
    pub fn new(label: impl Into<String>, stake: u64) -> BlockResult<Self> {
        let label = label.into();
        if stake == 0 {
            return Err("validator stake must be positive".to_string());
        }
        let account = account_record(&label);
        Ok(Self {
            validator_id: domain_hash("VALIDATOR-ID", &[HashPart::Str(&label)], 32),
            label,
            stake,
            consensus_public_key: domain_hash(
                "VALIDATOR-CONSENSUS-PUBLIC",
                &[HashPart::Str(&account.spend_public_key)],
                64,
            ),
            network_public_key: account.network_public_key,
            status: "active".to_string(),
            slashed_stake: 0,
            omission_count: 0,
            preconfirmation_miss_count: 0,
            block_challenge_count: 0,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "validator_id": self.validator_id,
            "label": self.label,
            "stake": self.stake,
            "consensus_public_key": self.consensus_public_key,
            "network_public_key": self.network_public_key,
            "status": self.status,
            "slashed_stake": self.slashed_stake,
            "omission_count": self.omission_count,
            "preconfirmation_miss_count": self.preconfirmation_miss_count,
            "block_challenge_count": self.block_challenge_count,
        })
    }

    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAvailabilityShard {
    pub shard_index: u64,
    pub shard_kind: String,
    pub data: String,
}

impl DataAvailabilityShard {
    pub fn data_hash(&self) -> String {
        domain_hash("DA-SHARD-DATA", &[HashPart::Str(&self.data)], 32)
    }

    pub fn byte_size(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_index": self.shard_index,
            "shard_kind": self.shard_kind,
            "data_hash": self.data_hash(),
            "byte_size": self.byte_size(),
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("DA shard public record object")
            .insert("data".to_string(), Value::String(self.data.clone()));
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAvailabilitySample {
    pub block_height: u64,
    pub tx_root: String,
    pub da_root: String,
    pub payload_hash: String,
    pub shard_index: u64,
    pub shard_kind: String,
    pub data_hash: String,
    pub byte_size: u64,
}

impl DataAvailabilitySample {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "data_availability_sample",
            "chain_id": CHAIN_ID,
            "block_height": self.block_height,
            "tx_root": self.tx_root,
            "da_root": self.da_root,
            "payload_hash": self.payload_hash,
            "shard_index": self.shard_index,
            "shard_kind": self.shard_kind,
            "data_hash": self.data_hash,
            "byte_size": self.byte_size,
        })
    }

    pub fn sample_root(&self) -> String {
        domain_hash("DA-SAMPLE", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAvailabilitySampleSet {
    pub block_height: u64,
    pub tx_root: String,
    pub da_root: String,
    pub sample_indices: Vec<u64>,
    pub sample_root: String,
    pub samples: Vec<DataAvailabilitySample>,
}

impl DataAvailabilitySampleSet {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "data_availability_sample_set",
            "chain_id": CHAIN_ID,
            "block_height": self.block_height,
            "tx_root": self.tx_root,
            "da_root": self.da_root,
            "sample_indices": self.sample_indices,
            "sample_root": self.sample_root,
            "samples": self.samples.iter().map(DataAvailabilitySample::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAvailabilityAttestation {
    pub validator_id: String,
    pub validator_stake: u64,
    pub signer_label: String,
    pub auth_scheme: String,
    pub auth_public_key: String,
    pub auth_transcript_hash: String,
    pub auth_signature: String,
}

impl DataAvailabilityAttestation {
    pub fn new(validator: &Validator, payload: &Value) -> Self {
        let authorization = sign_validator_authorization(
            &validator.label,
            "data_availability_attestation",
            payload,
        );
        Self {
            validator_id: validator.validator_id.clone(),
            validator_stake: validator.stake,
            signer_label: authorization.signer_label,
            auth_scheme: authorization.auth_scheme,
            auth_public_key: authorization.auth_public_key,
            auth_transcript_hash: authorization.auth_transcript_hash,
            auth_signature: authorization.auth_signature,
        }
    }

    pub fn authorization(&self) -> Authorization {
        Authorization {
            signer_label: self.signer_label.clone(),
            auth_scheme: self.auth_scheme.clone(),
            auth_public_key: self.auth_public_key.clone(),
            auth_transcript_hash: self.auth_transcript_hash.clone(),
            auth_signature: self.auth_signature.clone(),
        }
    }

    pub fn verify(&self, validator: &Validator, payload: &Value) -> bool {
        self.validator_id == validator.validator_id
            && self.validator_stake == validator.stake
            && verify_validator_authorization(
                &validator.consensus_public_key,
                "data_availability_attestation",
                payload,
                &self.authorization(),
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "validator_id": self.validator_id,
            "validator_stake": self.validator_stake,
            "signer_label": self.signer_label,
            "auth_scheme": self.auth_scheme,
            "auth_public_key": self.auth_public_key,
            "auth_transcript_hash": self.auth_transcript_hash,
            "auth_signature": self.auth_signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAvailabilityRecord {
    pub block_height: u64,
    pub tx_root: String,
    pub payload_hash: String,
    pub shard_size: u64,
    pub original_shard_count: u64,
    pub parity_shard_count: u64,
    pub original_bytes: u64,
    pub encoded_bytes: u64,
    pub shards: Vec<DataAvailabilityShard>,
    pub attestations: Vec<DataAvailabilityAttestation>,
}

impl DataAvailabilityRecord {
    pub fn shard_root(&self) -> String {
        merkle_root(
            "DA-SHARD",
            &self
                .shards
                .iter()
                .map(DataAvailabilityShard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "DA-ATTESTATION",
            &self
                .attestations
                .iter()
                .map(DataAvailabilityAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn da_root(&self) -> String {
        domain_hash(
            "DA",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.block_height as i128),
                HashPart::Str(&self.tx_root),
                HashPart::Str(&self.payload_hash),
                HashPart::Str(&self.shard_root()),
                HashPart::Str(&self.attestation_root()),
                HashPart::Int(self.original_bytes as i128),
                HashPart::Int(self.encoded_bytes as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "block_height": self.block_height,
            "tx_root": self.tx_root,
            "payload_hash": self.payload_hash,
            "da_root": self.da_root(),
            "shard_root": self.shard_root(),
            "attestation_root": self.attestation_root(),
            "shard_size": self.shard_size,
            "original_shard_count": self.original_shard_count,
            "parity_shard_count": self.parity_shard_count,
            "shard_count": self.shards.len(),
            "original_bytes": self.original_bytes,
            "encoded_bytes": self.encoded_bytes,
            "attestation_count": self.attestations.len(),
            "validator_stake_weight": self.validator_stake_weight(),
            "shards": self.shards.iter().map(DataAvailabilityShard::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.iter().map(DataAvailabilityAttestation::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record.as_object_mut().expect("DA record object").insert(
            "shards".to_string(),
            Value::Array(
                self.shards
                    .iter()
                    .map(DataAvailabilityShard::state_record)
                    .collect(),
            ),
        );
        record
    }

    pub fn validator_stake_weight(&self) -> u64 {
        self.attestations
            .iter()
            .map(|attestation| attestation.validator_stake)
            .sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorVote {
    pub validator_id: String,
    pub stake: u64,
    pub authorization: Authorization,
}

impl ValidatorVote {
    pub fn new(validator: &Validator, vote_payload: &Value) -> Self {
        Self {
            validator_id: validator.validator_id.clone(),
            stake: validator.stake,
            authorization: sign_validator_authorization(
                &validator.label,
                "validator_vote",
                vote_payload,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "validator_id": self.validator_id,
            "stake": self.stake,
            "signer_label": self.authorization.signer_label,
            "auth_scheme": self.authorization.auth_scheme,
            "auth_public_key": self.authorization.auth_public_key,
            "auth_transcript_hash": self.authorization.auth_transcript_hash,
            "auth_signature": self.authorization.auth_signature,
        })
    }

    pub fn verify(&self, domain: &str, payload: &Value) -> bool {
        verify_validator_authorization(
            &self.authorization.auth_public_key,
            domain,
            payload,
            &self.authorization,
        )
    }

    pub fn verify_for_validator(
        &self,
        validator: &Validator,
        domain: &str,
        payload: &Value,
    ) -> bool {
        self.validator_id == validator.validator_id
            && self.stake == validator.stake
            && verify_validator_authorization(
                &validator.consensus_public_key,
                domain,
                payload,
                &self.authorization,
            )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockStateRoots {
    pub note_root: String,
    pub nullifier_root: String,
    pub contract_root: String,
    pub wasm_runtime_root: String,
    pub account_root: String,
    pub asset_root: String,
    pub sealed_swap_settlement_receipt_root: String,
    pub bridge_root: String,
    pub fee_root: String,
    pub crypto_policy_root: String,
}

impl BlockStateRoots {
    pub fn empty() -> Self {
        Self {
            note_root: merkle_root("NOTE", &[]),
            nullifier_root: merkle_root("NULLIFIER", &[]),
            contract_root: merkle_root("CONTRACT", &[]),
            wasm_runtime_root: merkle_root("WASM-RUNTIME", &[]),
            account_root: merkle_root("ACCOUNT", &[]),
            asset_root: merkle_root("ASSET", &[]),
            sealed_swap_settlement_receipt_root: merkle_root("SEALED-SWAP-SETTLEMENT-RECEIPT", &[]),
            bridge_root: merkle_root("BRIDGE", &[]),
            fee_root: merkle_root("FEE", &[]),
            crypto_policy_root: crypto_policy_root(),
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "STATE",
            &[
                HashPart::Str(&self.note_root),
                HashPart::Str(&self.nullifier_root),
                HashPart::Str(&self.contract_root),
                HashPart::Str(&self.wasm_runtime_root),
                HashPart::Str(&self.account_root),
                HashPart::Str(&self.asset_root),
                HashPart::Str(&self.sealed_swap_settlement_receipt_root),
                HashPart::Str(&self.bridge_root),
                HashPart::Str(&self.fee_root),
                HashPart::Str(&self.crypto_policy_root),
            ],
            32,
        )
    }
}

impl Default for BlockStateRoots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2BlockHeader {
    pub version: u64,
    pub chain_id: String,
    pub height: u64,
    pub epoch: u64,
    pub timestamp_ms: u64,
    pub prev_block_hash: String,
    pub tx_root: String,
    pub mempool_admission_root: String,
    pub mempool_admission_count: u64,
    pub state_root: String,
    pub note_root: String,
    pub nullifier_root: String,
    pub contract_root: String,
    pub wasm_runtime_root: String,
    pub account_root: String,
    pub asset_root: String,
    pub sealed_swap_settlement_receipt_root: String,
    pub bridge_root: String,
    pub da_root: String,
    pub fee_root: String,
    pub crypto_policy_root: String,
    pub execution_profile: BlockExecutionProfile,
    pub proposer_id: String,
    pub validator_set_root: String,
    pub pq_vote_root: String,
    pub validator_vote_count: u64,
    pub validator_stake_weight: u64,
    pub soft_finality: bool,
}

impl L2BlockHeader {
    pub fn state_record(&self) -> Value {
        json!({
            "version": self.version,
            "chain_id": self.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "timestamp_ms": self.timestamp_ms,
            "prev_block_hash": self.prev_block_hash,
            "tx_root": self.tx_root,
            "mempool_admission_root": self.mempool_admission_root,
            "mempool_admission_count": self.mempool_admission_count,
            "state_root": self.state_root,
            "note_root": self.note_root,
            "nullifier_root": self.nullifier_root,
            "contract_root": self.contract_root,
            "wasm_runtime_root": self.wasm_runtime_root,
            "account_root": self.account_root,
            "asset_root": self.asset_root,
            "sealed_swap_settlement_receipt_root": self.sealed_swap_settlement_receipt_root,
            "bridge_root": self.bridge_root,
            "da_root": self.da_root,
            "fee_root": self.fee_root,
            "crypto_policy_root": self.crypto_policy_root,
            "execution_profile": self.execution_profile.public_record(),
            "proposer_id": self.proposer_id,
            "validator_set_root": self.validator_set_root,
            "pq_vote_root": self.pq_vote_root,
            "validator_vote_count": self.validator_vote_count,
            "validator_stake_weight": self.validator_stake_weight,
            "soft_finality": self.soft_finality,
        })
    }

    pub fn block_hash(&self) -> String {
        domain_hash(
            "L2-BLOCK-HEADER",
            &[HashPart::Json(&self.state_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.state_record();
        record
            .as_object_mut()
            .expect("block header state record object")
            .insert("block_hash".to_string(), Value::String(self.block_hash()));
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2Block {
    pub header: L2BlockHeader,
    pub transactions: Vec<Value>,
}

impl L2Block {
    pub fn public_record(&self) -> Value {
        json!({
            "header": self.header.public_record(),
            "transactions": self.transactions,
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "header": self.header.state_record(),
            "transactions": self.transactions,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockPrivacyProofAggregate {
    pub block_height: u64,
    pub block_hash: String,
    pub tx_root: String,
    pub privacy_proof_count: u64,
    pub proof_item_root: String,
    pub proof_system_root: String,
    pub aggregate_public_input_hash: String,
    pub aggregate_proof_system: String,
    pub aggregate_proof_root: String,
    pub proof_items: Vec<Value>,
}

impl BlockPrivacyProofAggregate {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "block_privacy_proof_aggregate",
            "chain_id": CHAIN_ID,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "tx_root": self.tx_root,
            "privacy_proof_count": self.privacy_proof_count,
            "proof_item_root": self.proof_item_root,
            "proof_system_root": self.proof_system_root,
            "aggregate_public_input_hash": self.aggregate_public_input_hash,
            "aggregate_proof_system": self.aggregate_proof_system,
            "aggregate_proof_root": self.aggregate_proof_root,
            "proof_items": self.proof_items,
        })
    }

    pub fn aggregate_root(&self) -> String {
        domain_hash(
            "BLOCK-PRIVACY-PROOF-AGGREGATE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("aggregate record object")
            .insert(
                "aggregate_root".to_string(),
                Value::String(self.aggregate_root()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockValidityCertificate {
    pub block_height: u64,
    pub block_hash: String,
    pub prev_block_hash: String,
    pub previous_state_root: String,
    pub state_root: String,
    pub tx_root: String,
    pub da_root: String,
    pub execution_profile_hash: String,
    pub privacy_proof_aggregate_root: String,
    pub privacy_proof_aggregate_proof_root: String,
    pub public_input_hash: String,
    pub proof_system: String,
    pub proof_root: String,
    pub prover_label: String,
    pub authorization: Authorization,
}

impl BlockValidityCertificate {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "block_validity_certificate",
            "chain_id": CHAIN_ID,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "prev_block_hash": self.prev_block_hash,
            "previous_state_root": self.previous_state_root,
            "state_root": self.state_root,
            "tx_root": self.tx_root,
            "da_root": self.da_root,
            "execution_profile_hash": self.execution_profile_hash,
            "privacy_proof_aggregate_root": self.privacy_proof_aggregate_root,
            "privacy_proof_aggregate_proof_root": self.privacy_proof_aggregate_proof_root,
            "public_input_hash": self.public_input_hash,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "prover_label": self.prover_label,
        })
    }

    pub fn certificate_root(&self) -> String {
        domain_hash(
            "BLOCK-VALIDITY-CERTIFICATE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("validity certificate record object");
        object.insert(
            "certificate_root".to_string(),
            Value::String(self.certificate_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_prover_authorization(
            &self.authorization.auth_public_key,
            "block_validity_certificate",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockBuildInput {
    pub height: u64,
    pub epoch: u64,
    pub timestamp_ms: u64,
    pub prev_block_hash: String,
    pub previous_state_root: String,
    pub transactions: Vec<Value>,
    pub mempool_admissions: Vec<Value>,
    pub state_roots: BlockStateRoots,
    pub fee_resources: Vec<FeeMarketResource>,
    pub validators: Vec<Validator>,
    pub proposer_label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducedBlock {
    pub block: L2Block,
    pub da_record: DataAvailabilityRecord,
    pub privacy_aggregate: BlockPrivacyProofAggregate,
    pub certificate: BlockValidityCertificate,
    pub validator_votes: Vec<ValidatorVote>,
    pub previous_state_root: String,
}

pub fn build_l2_block(input: BlockBuildInput) -> BlockResult<ProducedBlock> {
    let active_validators = active_validators(&input.validators)?;
    let proposer = active_validators
        .iter()
        .find(|validator| validator.label == input.proposer_label)
        .ok_or_else(|| "unknown or inactive proposer validator".to_string())?;

    let tx_root = merkle_root("TX", &input.transactions);
    let mempool_admission_root = merkle_root("MEMPOOL-ADMISSION", &input.mempool_admissions);
    let execution_profile = execution_profile_from_resources(&input.fee_resources);
    let da_record = build_data_availability_record(
        input.height,
        &tx_root,
        &input.transactions,
        &input.mempool_admissions,
        &execution_profile,
        &active_validators,
    );
    let da_root = da_record.da_root();
    let state_root = input.state_roots.state_root();
    let validator_set_root = merkle_root(
        "VALIDATOR-SET",
        &active_validators
            .iter()
            .map(Validator::public_record)
            .collect::<Vec<_>>(),
    );
    let vote_payload = validator_vote_payload(ValidatorVoteContext {
        height: input.height,
        epoch: input.epoch,
        prev_block_hash: &input.prev_block_hash,
        tx_root: &tx_root,
        mempool_admission_root: &mempool_admission_root,
        mempool_admission_count: input.mempool_admissions.len() as u64,
        state_roots: &input.state_roots,
        state_root: &state_root,
        da_root: &da_root,
        execution_profile: &execution_profile,
        proposer_id: &proposer.validator_id,
        validator_set_root: &validator_set_root,
    });
    let validator_votes = active_validators
        .iter()
        .map(|validator| ValidatorVote::new(validator, &vote_payload))
        .collect::<Vec<_>>();
    let pq_vote_root = merkle_root(
        "PQ-VOTE",
        &validator_votes
            .iter()
            .map(ValidatorVote::public_record)
            .collect::<Vec<_>>(),
    );
    let validator_stake_weight = validator_votes.iter().map(|vote| vote.stake).sum::<u64>();
    let total_stake = active_validators
        .iter()
        .map(|validator| validator.stake)
        .sum::<u64>();
    let soft_finality =
        total_stake > 0 && validator_stake_weight.saturating_mul(3) > total_stake.saturating_mul(2);

    let header = L2BlockHeader {
        version: 1,
        chain_id: CHAIN_ID.to_string(),
        height: input.height,
        epoch: input.epoch,
        timestamp_ms: input.timestamp_ms,
        prev_block_hash: input.prev_block_hash.clone(),
        tx_root,
        mempool_admission_root,
        mempool_admission_count: input.mempool_admissions.len() as u64,
        state_root,
        note_root: input.state_roots.note_root,
        nullifier_root: input.state_roots.nullifier_root,
        contract_root: input.state_roots.contract_root,
        wasm_runtime_root: input.state_roots.wasm_runtime_root,
        account_root: input.state_roots.account_root,
        asset_root: input.state_roots.asset_root,
        sealed_swap_settlement_receipt_root: input.state_roots.sealed_swap_settlement_receipt_root,
        bridge_root: input.state_roots.bridge_root,
        da_root,
        fee_root: input.state_roots.fee_root,
        crypto_policy_root: input.state_roots.crypto_policy_root,
        execution_profile,
        proposer_id: proposer.validator_id.clone(),
        validator_set_root,
        pq_vote_root,
        validator_vote_count: validator_votes.len() as u64,
        validator_stake_weight,
        soft_finality,
    };
    let block = L2Block {
        header,
        transactions: input.transactions,
    };
    let privacy_aggregate = build_privacy_proof_aggregate(&block);
    let certificate = build_validity_certificate(
        &block,
        &privacy_aggregate,
        &input.previous_state_root,
        &input.proposer_label,
    );
    Ok(ProducedBlock {
        block,
        da_record,
        privacy_aggregate,
        certificate,
        validator_votes,
        previous_state_root: input.previous_state_root,
    })
}

pub fn build_data_availability_record(
    height: u64,
    tx_root: &str,
    transactions: &[Value],
    mempool_admissions: &[Value],
    execution_profile: &BlockExecutionProfile,
    validators: &[Validator],
) -> DataAvailabilityRecord {
    let payload = data_availability_payload(
        height,
        tx_root,
        transactions,
        mempool_admissions,
        execution_profile,
    );
    let payload_hash = domain_hash("DA-PAYLOAD", &[HashPart::Str(&payload)], 32);
    let data_chunks = chunk_string(&payload, DEVNET_DA_SHARD_SIZE);
    let mut shards = data_chunks
        .into_iter()
        .enumerate()
        .map(|(index, data)| DataAvailabilityShard {
            shard_index: index as u64,
            shard_kind: "data".to_string(),
            data,
        })
        .collect::<Vec<_>>();
    let parity_count = std::cmp::max(1, shards.len().div_ceil(2));
    let data_hashes = Value::Array(
        shards
            .iter()
            .map(|shard| Value::String(shard.data_hash()))
            .collect(),
    );
    let parity_shards = (0..parity_count)
        .map(|index| DataAvailabilityShard {
            shard_index: (shards.len() + index) as u64,
            shard_kind: "parity".to_string(),
            data: domain_hash(
                "DA-PARITY-SHARD",
                &[
                    HashPart::Str(&payload_hash),
                    HashPart::Int(index as i128),
                    HashPart::Json(&data_hashes),
                ],
                64,
            ),
        })
        .collect::<Vec<_>>();
    let original_shard_count = shards.len() as u64;
    shards.extend(parity_shards);
    let original_bytes = payload.len() as u64;
    let encoded_bytes = shards
        .iter()
        .map(DataAvailabilityShard::byte_size)
        .sum::<u64>();
    let mut unsigned_record = DataAvailabilityRecord {
        block_height: height,
        tx_root: tx_root.to_string(),
        payload_hash,
        shard_size: DEVNET_DA_SHARD_SIZE as u64,
        original_shard_count,
        parity_shard_count: parity_count as u64,
        original_bytes,
        encoded_bytes,
        shards,
        attestations: Vec::new(),
    };
    let attestation_payload = data_availability_attestation_payload(&unsigned_record);
    unsigned_record.attestations = validators
        .iter()
        .map(|validator| DataAvailabilityAttestation::new(validator, &attestation_payload))
        .collect();
    unsigned_record
}

pub fn data_availability_payload(
    height: u64,
    tx_root: &str,
    transactions: &[Value],
    mempool_admissions: &[Value],
    execution_profile: &BlockExecutionProfile,
) -> String {
    canonical_json_string(&json!({
        "chain_id": CHAIN_ID,
        "height": height,
        "tx_root": tx_root,
        "mempool_admission_root": merkle_root("MEMPOOL-ADMISSION", mempool_admissions),
        "mempool_admission_count": mempool_admissions.len(),
        "mempool_admissions": mempool_admissions,
        "transactions": transactions,
        "execution_profile": execution_profile.public_record(),
    }))
}

pub fn data_availability_attestation_payload(record: &DataAvailabilityRecord) -> Value {
    json!({
        "chain_id": CHAIN_ID,
        "block_height": record.block_height,
        "tx_root": record.tx_root,
        "payload_hash": record.payload_hash,
        "shard_root": record.shard_root(),
        "shard_count": record.shards.len(),
        "encoded_bytes": record.encoded_bytes,
    })
}

pub fn sample_data_availability(
    record: &DataAvailabilityRecord,
    shard_index: u64,
) -> BlockResult<DataAvailabilitySample> {
    let shard = record
        .shards
        .iter()
        .find(|shard| shard.shard_index == shard_index)
        .ok_or_else(|| "unknown DA shard index".to_string())?;
    Ok(DataAvailabilitySample {
        block_height: record.block_height,
        tx_root: record.tx_root.clone(),
        da_root: record.da_root(),
        payload_hash: record.payload_hash.clone(),
        shard_index: shard.shard_index,
        shard_kind: shard.shard_kind.clone(),
        data_hash: shard.data_hash(),
        byte_size: shard.byte_size(),
    })
}

pub fn sample_data_availability_set(
    record: &DataAvailabilityRecord,
    shard_indices: &[u64],
) -> BlockResult<DataAvailabilitySampleSet> {
    if shard_indices.is_empty() {
        return Err("DA sample set requires at least one shard index".to_string());
    }
    let mut unique = BTreeSet::new();
    let mut samples = Vec::new();
    for shard_index in shard_indices {
        if !unique.insert(*shard_index) {
            return Err("duplicate DA sample shard index".to_string());
        }
        samples.push(sample_data_availability(record, *shard_index)?);
    }
    samples.sort_by_key(|sample| sample.shard_index);
    let sample_indices = samples
        .iter()
        .map(|sample| sample.shard_index)
        .collect::<Vec<_>>();
    let sample_root = sampled_da_shard_root(record, &sample_indices)?;
    Ok(DataAvailabilitySampleSet {
        block_height: record.block_height,
        tx_root: record.tx_root.clone(),
        da_root: record.da_root(),
        sample_indices,
        sample_root,
        samples,
    })
}

pub fn sampled_da_shard_root(
    record: &DataAvailabilityRecord,
    shard_indices: &[u64],
) -> BlockResult<String> {
    let samples = shard_indices
        .iter()
        .map(|index| sample_data_availability(record, *index))
        .collect::<BlockResult<Vec<_>>>()?;
    Ok(merkle_root(
        "DA-SAMPLED-SHARD",
        &samples
            .iter()
            .map(DataAvailabilitySample::public_record)
            .collect::<Vec<_>>(),
    ))
}

pub fn data_availability_record_root(records: &[DataAvailabilityRecord]) -> String {
    merkle_root(
        "DA-RECORD",
        &records
            .iter()
            .map(DataAvailabilityRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn build_privacy_proof_aggregate(block: &L2Block) -> BlockPrivacyProofAggregate {
    let proof_items = privacy_proof_items_for_block(block);
    let proof_item_root = merkle_root("BLOCK-PRIVACY-PROOF-ITEM", &proof_items);
    let proof_system_records = proof_items
        .iter()
        .map(|item| {
            json!({
                "tx_index": item["tx_index"],
                "proof_system": item.get("proof_system").cloned().unwrap_or_else(|| Value::String("unknown".to_string())),
            })
        })
        .collect::<Vec<_>>();
    let proof_system_root = merkle_root("BLOCK-PRIVACY-PROOF-SYSTEM", &proof_system_records);
    let aggregate_inputs = json!({
        "chain_id": CHAIN_ID,
        "block_height": block.header.height,
        "block_hash": block.header.block_hash(),
        "tx_root": block.header.tx_root,
        "privacy_proof_count": proof_items.len(),
        "proof_item_root": proof_item_root,
        "proof_system_root": proof_system_root,
        "execution_profile_proof_count": block.header.execution_profile.privacy_proof_count,
    });
    let aggregate_public_input_hash = domain_hash(
        "BLOCK-PRIVACY-PROOF-AGGREGATE-PUBLIC-INPUT",
        &[HashPart::Json(&aggregate_inputs)],
        32,
    );
    let aggregate_proof_system = "devnet-transparent-privacy-proof-aggregate".to_string();
    let aggregate_proof_root = domain_hash(
        "DEVNET-PRIVACY-PROOF-AGGREGATE",
        &[
            HashPart::Str(&aggregate_proof_system),
            HashPart::Str(&aggregate_public_input_hash),
            HashPart::Str(&proof_item_root),
            HashPart::Str(&proof_system_root),
        ],
        32,
    );
    BlockPrivacyProofAggregate {
        block_height: block.header.height,
        block_hash: block.header.block_hash(),
        tx_root: block.header.tx_root.clone(),
        privacy_proof_count: proof_items.len() as u64,
        proof_item_root,
        proof_system_root,
        aggregate_public_input_hash,
        aggregate_proof_system,
        aggregate_proof_root,
        proof_items,
    }
}

pub fn validity_public_inputs(
    block: &L2Block,
    aggregate: &BlockPrivacyProofAggregate,
    previous_state_root: &str,
) -> Value {
    json!({
        "kind": "state_transition_public_inputs",
        "chain_id": CHAIN_ID,
        "block_height": block.header.height,
        "block_hash": block.header.block_hash(),
        "prev_block_hash": block.header.prev_block_hash,
        "previous_state_root": previous_state_root,
        "state_root": block.header.state_root,
        "tx_root": block.header.tx_root,
        "mempool_admission_root": block.header.mempool_admission_root,
        "note_root": block.header.note_root,
        "nullifier_root": block.header.nullifier_root,
        "contract_root": block.header.contract_root,
        "wasm_runtime_root": block.header.wasm_runtime_root,
        "account_root": block.header.account_root,
        "asset_root": block.header.asset_root,
        "sealed_swap_settlement_receipt_root": block.header.sealed_swap_settlement_receipt_root,
        "bridge_root": block.header.bridge_root,
        "da_root": block.header.da_root,
        "fee_root": block.header.fee_root,
        "crypto_policy_root": block.header.crypto_policy_root,
        "execution_profile": block.header.execution_profile.public_record(),
        "privacy_proof_aggregate_root": aggregate.aggregate_root(),
        "privacy_proof_aggregate_proof_root": aggregate.aggregate_proof_root,
        "validator_set_root": block.header.validator_set_root,
        "pq_vote_root": block.header.pq_vote_root,
        "transaction_count": block.transactions.len(),
    })
}

pub fn build_validity_certificate(
    block: &L2Block,
    aggregate: &BlockPrivacyProofAggregate,
    previous_state_root: &str,
    prover_label: &str,
) -> BlockValidityCertificate {
    let public_inputs = validity_public_inputs(block, aggregate, previous_state_root);
    let public_input_hash = domain_hash(
        "STATE-TRANSITION-PUBLIC-INPUT",
        &[HashPart::Json(&public_inputs)],
        32,
    );
    let proof_system = "devnet-transparent-state-transition-proof".to_string();
    let proof_root = domain_hash(
        "DEVNET-STATE-TRANSITION-PROOF",
        &[
            HashPart::Str(&proof_system),
            HashPart::Str(&public_input_hash),
            HashPart::Str(&block.header.validator_set_root),
            HashPart::Str(&block.header.pq_vote_root),
        ],
        32,
    );
    let execution_profile_record = block.header.execution_profile.public_record();
    let mut certificate = BlockValidityCertificate {
        block_height: block.header.height,
        block_hash: block.header.block_hash(),
        prev_block_hash: block.header.prev_block_hash.clone(),
        previous_state_root: previous_state_root.to_string(),
        state_root: block.header.state_root.clone(),
        tx_root: block.header.tx_root.clone(),
        da_root: block.header.da_root.clone(),
        execution_profile_hash: domain_hash(
            "EXECUTION-PROFILE",
            &[HashPart::Json(&execution_profile_record)],
            32,
        ),
        privacy_proof_aggregate_root: aggregate.aggregate_root(),
        privacy_proof_aggregate_proof_root: aggregate.aggregate_proof_root.clone(),
        public_input_hash,
        proof_system,
        proof_root,
        prover_label: prover_label.to_string(),
        authorization: Authorization {
            signer_label: prover_label.to_string(),
            auth_scheme: CryptoRole::ProverSignature.scheme().to_string(),
            auth_public_key: String::new(),
            auth_transcript_hash: String::new(),
            auth_signature: String::new(),
        },
    };
    certificate.authorization = sign_prover_authorization(
        prover_label,
        "block_validity_certificate",
        &certificate.unsigned_record(),
    );
    certificate
}

pub fn verify_validity_certificate(
    block: &L2Block,
    aggregate: &BlockPrivacyProofAggregate,
    previous_state_root: &str,
    certificate: &BlockValidityCertificate,
) -> bool {
    let expected = build_validity_certificate(
        block,
        aggregate,
        previous_state_root,
        &certificate.prover_label,
    );
    expected.unsigned_record() == certificate.unsigned_record()
        && expected.authorization == certificate.authorization
        && certificate.verify_authorization()
}

fn active_validators(validators: &[Validator]) -> BlockResult<Vec<Validator>> {
    let mut active = validators
        .iter()
        .filter(|validator| validator.is_active())
        .cloned()
        .collect::<Vec<_>>();
    active.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    if active.is_empty() {
        return Err("block production requires at least one active validator".to_string());
    }
    let mut seen = BTreeSet::new();
    if active
        .iter()
        .any(|validator| !seen.insert(validator.validator_id.clone()))
    {
        return Err("duplicate validator id".to_string());
    }
    Ok(active)
}

struct ValidatorVoteContext<'a> {
    height: u64,
    epoch: u64,
    prev_block_hash: &'a str,
    tx_root: &'a str,
    mempool_admission_root: &'a str,
    mempool_admission_count: u64,
    state_roots: &'a BlockStateRoots,
    state_root: &'a str,
    da_root: &'a str,
    execution_profile: &'a BlockExecutionProfile,
    proposer_id: &'a str,
    validator_set_root: &'a str,
}

fn validator_vote_payload(context: ValidatorVoteContext<'_>) -> Value {
    json!({
        "chain_id": CHAIN_ID,
        "height": context.height,
        "epoch": context.epoch,
        "prev_block_hash": context.prev_block_hash,
        "tx_root": context.tx_root,
        "mempool_admission_root": context.mempool_admission_root,
        "mempool_admission_count": context.mempool_admission_count,
        "state_root": context.state_root,
        "note_root": context.state_roots.note_root,
        "nullifier_root": context.state_roots.nullifier_root,
        "contract_root": context.state_roots.contract_root,
        "wasm_runtime_root": context.state_roots.wasm_runtime_root,
        "account_root": context.state_roots.account_root,
        "asset_root": context.state_roots.asset_root,
        "sealed_swap_settlement_receipt_root": context.state_roots.sealed_swap_settlement_receipt_root,
        "bridge_root": context.state_roots.bridge_root,
        "da_root": context.da_root,
        "fee_root": context.state_roots.fee_root,
        "crypto_policy_root": context.state_roots.crypto_policy_root,
        "execution_profile": context.execution_profile.public_record(),
        "proposer_id": context.proposer_id,
        "validator_set_root": context.validator_set_root,
    })
}

fn privacy_proof_items_for_block(block: &L2Block) -> Vec<Value> {
    block
        .transactions
        .iter()
        .enumerate()
        .filter_map(|(tx_index, tx)| {
            let proof_bundle = tx.get("proof_bundle")?;
            if proof_bundle.is_null() {
                return None;
            }
            let proof_object = proof_bundle.as_object()?;
            let mut item = Map::new();
            item.insert("tx_index".to_string(), json!(tx_index));
            item.insert(
                "tx_kind".to_string(),
                Value::String(
                    tx.get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                ),
            );
            item.insert(
                "tx_public_hash".to_string(),
                Value::String(domain_hash("TX-PUBLIC", &[HashPart::Json(tx)], 32)),
            );
            for (key, value) in proof_object {
                if key != "private_witness_hash" {
                    item.insert(key.clone(), value.clone());
                }
            }
            Some(Value::Object(item))
        })
        .collect()
}

fn chunk_string(input: &str, max_bytes: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_bytes = 0;
    for character in input.chars() {
        let character_bytes = character.len_utf8();
        if current_bytes + character_bytes > max_bytes && !current.is_empty() {
            chunks.push(current);
            current = String::new();
            current_bytes = 0;
        }
        current.push(character);
        current_bytes += character_bytes;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::{ContractCallRequest, ContractState},
        crypto_policy::crypto_policy_root,
        defi::DefiState,
        hash::merkle_root,
    };

    fn integrated_roots(defi: &DefiState, contracts: &ContractState) -> BlockStateRoots {
        BlockStateRoots {
            note_root: defi.note_root(),
            nullifier_root: merkle_root("NULLIFIER", &[]),
            contract_root: contracts.contract_state_root(),
            wasm_runtime_root: merkle_root("WASM-RUNTIME", &[]),
            account_root: merkle_root("ACCOUNT", &[]),
            asset_root: defi.asset_root(),
            sealed_swap_settlement_receipt_root: defi.sealed_swap_settlement_receipt_root(),
            bridge_root: merkle_root("BRIDGE", &[]),
            fee_root: defi.fee_root(),
            crypto_policy_root: crypto_policy_root(),
        }
    }

    #[test]
    fn block_header_commits_defi_contract_da_votes_and_validity_certificate() {
        let mut defi = DefiState::new();
        let asset = defi
            .create_native_asset("DGR", "issuer:treasury-key", 1_500)
            .unwrap();
        let mint = defi
            .submit_asset_mint(&asset.asset_id, "alice-view-key", 1_000, None)
            .unwrap();

        let mut contracts = ContractState::new();
        let contract = contracts
            .deploy_counter_contract("alice-view-key", 100, false)
            .unwrap();
        let applied = contracts
            .execute_contract_call(
                ContractCallRequest::new(
                    &contract.contract_id,
                    "increment",
                    json!({"amount": 17}),
                    "bob-view-key",
                    20,
                )
                .private_args(true)
                .fee_asset(&asset.asset_id, None),
            )
            .unwrap();

        let validators = vec![
            Validator::new("devnet-proposer", 1_000).unwrap(),
            Validator::new("validator-two", 500).unwrap(),
        ];
        let input = BlockBuildInput {
            height: 0,
            epoch: 0,
            timestamp_ms: 1_700_000_000_000,
            prev_block_hash: "GENESIS".to_string(),
            previous_state_root: "GENESIS".to_string(),
            transactions: vec![mint.public_record(), applied.call.public_record()],
            mempool_admissions: vec![json!({
                "kind": "mempool_admission",
                "tx_kind": "contract_call",
                "tx_hash": applied.call.args_commitment(),
            })],
            state_roots: integrated_roots(&defi, &contracts),
            fee_resources: vec![applied.fee_resource.clone()],
            validators,
            proposer_label: "devnet-proposer".to_string(),
        };
        let produced = build_l2_block(input).unwrap();
        let header = &produced.block.header;

        assert_eq!(header.height, 0);
        assert_eq!(header.prev_block_hash, "GENESIS");
        assert_eq!(header.validator_vote_count, 2);
        assert_eq!(header.validator_stake_weight, 1_500);
        assert!(header.soft_finality);
        assert_eq!(header.execution_profile.tx_count, 1);
        assert_eq!(header.execution_profile.contract_call_count, 1);
        assert_eq!(header.execution_profile.privacy_proof_count, 1);
        assert_eq!(produced.da_record.original_shard_count, 6);
        assert_eq!(produced.da_record.parity_shard_count, 3);
        assert_eq!(produced.da_record.attestations.len(), 2);
        assert_eq!(produced.privacy_aggregate.privacy_proof_count, 1);
        assert!(produced.certificate.verify_authorization());
        assert!(verify_validity_certificate(
            &produced.block,
            &produced.privacy_aggregate,
            "GENESIS",
            &produced.certificate
        ));
        assert_eq!(header.tx_root.len(), 64);
        assert_eq!(header.state_root.len(), 64);
        assert_eq!(header.da_root, produced.da_record.da_root());
        assert_eq!(header.block_hash().len(), 64);
    }

    #[test]
    fn certificate_detects_tampered_state_root() {
        let validator = Validator::new("devnet-proposer", 1_000).unwrap();
        let input = BlockBuildInput {
            height: 7,
            epoch: 0,
            timestamp_ms: 1_700_000_000_500,
            prev_block_hash: "previous".to_string(),
            previous_state_root: "previous-state".to_string(),
            transactions: vec![json!({"kind": "noop", "nonce": 1})],
            mempool_admissions: Vec::new(),
            state_roots: BlockStateRoots::empty(),
            fee_resources: vec![FeeMarketResource::operation("noop", 1, "")],
            validators: vec![validator],
            proposer_label: "devnet-proposer".to_string(),
        };
        let produced = build_l2_block(input).unwrap();
        let mut tampered_block = produced.block.clone();
        tampered_block.header.state_root = domain_hash("TAMPERED", &[], 32);

        assert!(!verify_validity_certificate(
            &tampered_block,
            &produced.privacy_aggregate,
            &produced.previous_state_root,
            &produced.certificate
        ));
    }

    #[test]
    fn validator_and_da_records_match_python_id_conventions() {
        let validator = Validator::new("devnet-proposer", 1_000).unwrap();
        assert_eq!(
            validator.validator_id,
            "23c40143445ee774227e27713be435ac57a36ada51e1e7da83013fe2519474b9"
        );
        assert_eq!(validator.public_record()["status"], "active");

        let profile = BlockExecutionProfile::empty();
        let tx_root = merkle_root("TX", &[]);
        let da = build_data_availability_record(0, &tx_root, &[], &[], &profile, &[validator]);
        assert_eq!(da.shard_size, 512);
        assert_eq!(da.original_shard_count, 2);
        assert_eq!(da.parity_shard_count, 1);
        assert_eq!(da.validator_stake_weight(), 1_000);
        assert_eq!(da.da_root().len(), 64);
    }
}
