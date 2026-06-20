use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    fees::FeeMarketResource,
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DefiResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub asset_id: String,
    pub symbol: String,
    pub issuer_policy: String,
    pub supply_policy: String,
    pub privacy_class: String,
    pub metadata_hash: String,
    pub max_supply: u64,
}

impl Asset {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "symbol": self.symbol,
            "issuer_policy": self.issuer_policy,
            "supply_policy": self.supply_policy,
            "privacy_class": self.privacy_class,
            "metadata_hash": self.metadata_hash,
            "max_supply": self.max_supply,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetSupply {
    pub asset_id: String,
    pub minted_amount: u64,
    pub burned_amount: u64,
}

impl AssetSupply {
    pub fn new(asset_id: &str) -> Self {
        Self {
            asset_id: asset_id.to_string(),
            minted_amount: 0,
            burned_amount: 0,
        }
    }

    pub fn circulating_amount(&self) -> u64 {
        self.minted_amount - self.burned_amount
    }

    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "minted_amount": self.minted_amount,
            "burned_amount": self.burned_amount,
            "circulating_amount": self.circulating_amount(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub note_id: String,
    pub owner_view_key: String,
    pub asset_id: String,
    pub amount: u64,
    pub blinding: String,
    pub commitment: String,
}

impl Note {
    pub fn create(owner_view_key: &str, asset_id: &str, amount: u64, nonce: u64) -> Self {
        let blinding = domain_hash(
            "NOTE-BLINDING",
            &[
                HashPart::Str(owner_view_key),
                HashPart::Str(asset_id),
                HashPart::Int(amount as i128),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let owner_commitment =
            domain_hash("OWNER-COMMITMENT", &[HashPart::Str(owner_view_key)], 32);
        let asset_commitment = domain_hash("ASSET-COMMITMENT", &[HashPart::Str(asset_id)], 32);
        let amount_commitment = domain_hash(
            "AMOUNT-COMMITMENT",
            &[HashPart::Int(amount as i128), HashPart::Str(&blinding)],
            32,
        );
        let commitment = domain_hash(
            "NOTE-COMMITMENT",
            &[
                HashPart::Str(&owner_commitment),
                HashPart::Str(&asset_commitment),
                HashPart::Str(&amount_commitment),
            ],
            32,
        );
        let note_id = domain_hash(
            "NOTE-ID",
            &[HashPart::Str(&commitment), HashPart::Int(nonce as i128)],
            32,
        );
        Self {
            note_id,
            owner_view_key: owner_view_key.to_string(),
            asset_id: asset_id.to_string(),
            amount,
            blinding,
            commitment,
        }
    }

    pub fn wallet_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "commitment": self.commitment,
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_view_key": self.owner_view_key,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "blinding": self.blinding,
            "commitment": self.commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyProof {
    pub proof_system: String,
    pub public_input_hash: String,
    pub private_witness_hash: String,
    pub proof_root: String,
}

impl PrivacyProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_system": self.proof_system,
            "public_input_hash": self.public_input_hash,
            "proof_root": self.proof_root,
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "proof_system": self.proof_system,
            "public_input_hash": self.public_input_hash,
            "private_witness_hash": self.private_witness_hash,
            "proof_root": self.proof_root,
        })
    }
}

pub fn build_privacy_proof(
    proof_system: &str,
    public_inputs: &Value,
    private_witnesses: &Value,
) -> PrivacyProof {
    let public_input_hash = domain_hash(
        "PRIVACY-PUBLIC-INPUTS",
        &[HashPart::Json(public_inputs)],
        32,
    );
    let private_witness_hash = domain_hash(
        "PRIVACY-PRIVATE-WITNESSES",
        &[HashPart::Json(private_witnesses)],
        32,
    );
    let proof_root = domain_hash(
        "PRIVACY-PROOF",
        &[
            HashPart::Str(proof_system),
            HashPart::Str(&public_input_hash),
            HashPart::Str(&private_witness_hash),
        ],
        32,
    );
    PrivacyProof {
        proof_system: proof_system.to_string(),
        public_input_hash,
        private_witness_hash,
        proof_root,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetMint {
    pub asset_id: String,
    pub amount: u64,
    pub output_note: Note,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
}

impl AssetMint {
    pub fn mint_id(&self) -> String {
        domain_hash(
            "ASSET-MINT-ID",
            &[
                HashPart::Str(&self.asset_id),
                HashPart::Int(self.amount as i128),
                HashPart::Str(&self.output_note.commitment),
            ],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "asset_mint",
            "asset_id": self.asset_id,
            "amount": self.amount,
            "mint_id": self.mint_id(),
            "output_commitment": self.output_note.commitment,
            "proof_system": self.proof_system,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("asset mint record object");
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

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record.as_object_mut().expect("asset mint state object");
        object.insert("output_note".to_string(), self.output_note.state_record());
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetBurn {
    pub spent_note_id: String,
    pub nullifier: String,
    pub asset_id: String,
    pub amount: u64,
    pub output_notes: Vec<Note>,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl AssetBurn {
    pub fn terms_hash(&self) -> String {
        let commitments = self
            .output_notes
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect::<Vec<_>>();
        let commitments_value = Value::Array(commitments);
        domain_hash(
            "ASSET-BURN-TERMS",
            &[
                HashPart::Str(&self.asset_id),
                HashPart::Int(self.amount as i128),
                HashPart::Json(&commitments_value),
            ],
            32,
        )
    }

    pub fn unsigned_record(&self, include_spent_note: bool) -> Value {
        let output_commitments = self
            .output_notes
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect::<Vec<_>>();
        let mut record = json!({
            "kind": "asset_burn",
            "nullifier": self.nullifier,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "terms_hash": self.terms_hash(),
            "output_commitments": output_commitments,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_note {
            record
                .as_object_mut()
                .expect("asset burn record object")
                .insert(
                    "spent_note_id".to_string(),
                    Value::String(self.spent_note_id.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record(false);
        let object = record.as_object_mut().expect("asset burn record object");
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

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record.as_object_mut().expect("asset burn state object");
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmPool {
    pub pool_id: String,
    pub asset_a_id: String,
    pub asset_b_id: String,
    pub lp_asset_id: String,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub total_lp: u64,
    pub fee_bps: u64,
    pub curve: String,
}

impl AmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "asset_a_id": self.asset_a_id,
            "asset_b_id": self.asset_b_id,
            "lp_asset_id": self.lp_asset_id,
            "reserve_a": self.reserve_a,
            "reserve_b": self.reserve_b,
            "total_lp": self.total_lp,
            "fee_bps": self.fee_bps,
            "curve": self.curve,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmLiquidityAdd {
    pub pool_id: String,
    pub spent_note_a_id: String,
    pub spent_note_b_id: String,
    pub nullifier_a: String,
    pub nullifier_b: String,
    pub amount_a: u64,
    pub amount_b: u64,
    pub lp_minted: u64,
    pub output_notes: Vec<Note>,
    pub network_fee: u64,
    pub encrypted_payload_hash: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl AmmLiquidityAdd {
    pub fn unsigned_record(&self, include_spent_notes: bool) -> Value {
        let output_commitments = self
            .output_notes
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect::<Vec<_>>();
        let mut record = json!({
            "kind": "amm_liquidity_add",
            "pool_id": self.pool_id,
            "nullifiers": [self.nullifier_a, self.nullifier_b],
            "amount_a": self.amount_a,
            "amount_b": self.amount_b,
            "lp_minted": self.lp_minted,
            "output_commitments": output_commitments,
            "network_fee": self.network_fee,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_notes {
            let object = record.as_object_mut().expect("AMM liquidity record object");
            object.insert(
                "spent_note_a_id".to_string(),
                Value::String(self.spent_note_a_id.clone()),
            );
            object.insert(
                "spent_note_b_id".to_string(),
                Value::String(self.spent_note_b_id.clone()),
            );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(false), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record
            .as_object_mut()
            .expect("AMM liquidity state record object");
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmSwap {
    pub pool_id: String,
    pub spent_note_id: String,
    pub nullifier: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub amount_in: u64,
    pub amount_out: u64,
    pub output_notes: Vec<Note>,
    pub network_fee: u64,
    pub encrypted_payload_hash: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl AmmSwap {
    pub fn unsigned_record(&self, include_spent_note: bool) -> Value {
        let output_commitments = self
            .output_notes
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect::<Vec<_>>();
        let mut record = json!({
            "kind": "amm_swap",
            "pool_id": self.pool_id,
            "nullifier": self.nullifier,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "amount_in": self.amount_in,
            "amount_out": self.amount_out,
            "output_commitments": output_commitments,
            "network_fee": self.network_fee,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_note {
            record
                .as_object_mut()
                .expect("AMM swap record object")
                .insert(
                    "spent_note_id".to_string(),
                    Value::String(self.spent_note_id.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(false), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record
            .as_object_mut()
            .expect("AMM swap state record object");
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmBatchSwap {
    pub pool_id: String,
    pub spent_note_ids: Vec<String>,
    pub nullifiers: Vec<String>,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub amount_ins: Vec<u64>,
    pub total_amount_in: u64,
    pub total_amount_out: u64,
    pub output_notes: Vec<Note>,
    pub network_fee: u64,
    pub encrypted_payload_hash: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl AmmBatchSwap {
    pub fn unsigned_record(&self, include_spent_notes: bool) -> Value {
        let mut record = json!({
            "kind": "amm_batch_swap",
            "pool_id": self.pool_id,
            "nullifiers": self.nullifiers,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "amount_ins": self.amount_ins,
            "total_amount_in": self.total_amount_in,
            "total_amount_out": self.total_amount_out,
            "output_commitments": output_commitments(&self.output_notes),
            "network_fee": self.network_fee,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_notes {
            record
                .as_object_mut()
                .expect("AMM batch swap record object")
                .insert("spent_note_ids".to_string(), json!(self.spent_note_ids));
        }
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(false), &self.authorization);
        record
            .as_object_mut()
            .expect("AMM batch swap public record object")
            .insert("input_count".to_string(), json!(self.spent_note_ids.len()));
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record
            .as_object_mut()
            .expect("AMM batch swap state record object");
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSwapIntentReveal {
    pub commitment_id: String,
    pub spent_note_id: String,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub recipient_view_key: String,
    pub network_fee: u64,
    pub reveal_secret: String,
    pub signer_label: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSwapIntent {
    pub pool_id: String,
    pub spent_note_id: String,
    pub nullifier: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub recipient_view_key: String,
    pub network_fee: u64,
    pub signer_label: String,
    pub authorization: Authorization,
}

impl SealedSwapIntent {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "sealed_amm_swap_intent",
            "pool_id": self.pool_id,
            "nullifier": self.nullifier,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "amount_in": self.amount_in,
            "min_amount_out": self.min_amount_out,
            "recipient_commitment": sealed_swap_recipient_commitment(&self.recipient_view_key),
            "network_fee": self.network_fee,
        })
    }

    pub fn intent_hash(&self) -> String {
        domain_hash(
            "SEALED-AMM-SWAP-INTENT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = json!({
            "intent_hash": self.intent_hash(),
            "nullifier": self.nullifier,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
        });
        record = signed_public_record(record, &self.authorization);
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("sealed swap intent state record object");
        object.insert(
            "spent_note_id".to_string(),
            Value::String(self.spent_note_id.clone()),
        );
        object.insert(
            "recipient_view_key".to_string(),
            Value::String(self.recipient_view_key.clone()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        signed_public_record(record, &self.authorization)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSwapFill {
    pub intent: SealedSwapIntent,
    pub amount_out: u64,
    pub output_note: Note,
    pub change_note: Option<Note>,
}

impl SealedSwapFill {
    pub fn output_notes(&self) -> Vec<Note> {
        let mut notes = vec![self.output_note.clone()];
        if let Some(change_note) = &self.change_note {
            notes.push(change_note.clone());
        }
        notes
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent": self.intent.public_record(),
            "output_commitment": self.output_note.commitment,
            "change_commitment": self.change_note.as_ref().map(|note| note.commitment.clone()).unwrap_or_default(),
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "intent": self.intent.state_record(),
            "amount_out": self.amount_out,
            "output_note": self.output_note.state_record(),
            "change_note": self.change_note.as_ref().map(Note::state_record),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmSealedBatchSwap {
    pub pool_id: String,
    pub fills: Vec<SealedSwapFill>,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub total_amount_in: u64,
    pub total_amount_out: u64,
    pub network_fee_total: u64,
    pub encrypted_payload_hash: String,
    pub commitment_ids: Vec<String>,
    pub commitment_reveal_secrets: Vec<String>,
    pub solver_bid_id: String,
    pub solver_label: String,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl AmmSealedBatchSwap {
    pub fn intent_root(&self) -> String {
        merkle_root(
            "SEALED-AMM-SWAP-INTENT",
            &self
                .fills
                .iter()
                .map(|fill| fill.intent.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn commitment_root(&self) -> String {
        sealed_swap_batch_commitment_root(&self.commitment_ids)
    }

    pub fn output_notes(&self) -> Vec<Note> {
        self.fills
            .iter()
            .flat_map(SealedSwapFill::output_notes)
            .collect()
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "sealed_amm_batch_swap",
            "pool_id": self.pool_id,
            "intent_count": self.fills.len(),
            "intent_root": self.intent_root(),
            "nullifiers": self.fills.iter().map(|fill| fill.intent.nullifier.clone()).collect::<Vec<_>>(),
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "total_amount_in": self.total_amount_in,
            "total_amount_out": self.total_amount_out,
            "network_fee_total": self.network_fee_total,
            "commitment_count": self.commitment_ids.len(),
            "commitment_root": self.commitment_root(),
            "solver_bid_id": self.solver_bid_id,
            "output_commitments": output_commitments(&self.output_notes()),
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "solver_commitment": sealed_swap_solver_commitment(&self.solver_label),
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        self.unsigned_record()
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("sealed AMM batch swap state record object");
        object.insert(
            "fills".to_string(),
            Value::Array(
                self.fills
                    .iter()
                    .map(SealedSwapFill::state_record)
                    .collect(),
            ),
        );
        object.insert(
            "commitment_ids".to_string(),
            Value::Array(
                self.commitment_ids
                    .iter()
                    .map(|id| Value::String(id.clone()))
                    .collect(),
            ),
        );
        object.insert(
            "commitment_reveal_secrets".to_string(),
            Value::Array(
                self.commitment_reveal_secrets
                    .iter()
                    .map(|secret| Value::String(secret.clone()))
                    .collect(),
            ),
        );
        object.insert(
            "solver_label".to_string(),
            Value::String(self.solver_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSwapSettlementReceipt {
    pub receipt_id: String,
    pub block_height: u64,
    pub tx_public_hash: String,
    pub pool_id: String,
    pub solver_label: String,
    pub intent_count: u64,
    pub intent_root: String,
    pub route_commitment: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub total_amount_in: u64,
    pub total_amount_out: u64,
    pub network_fee_total: u64,
    pub pool_fee_bps: u64,
    pub pool_before_root: String,
    pub pool_after_root: String,
    pub pool_before_reserve_in: u64,
    pub pool_before_reserve_out: u64,
    pub pool_after_reserve_in: u64,
    pub pool_after_reserve_out: u64,
    pub fill_commitment_root: String,
    pub minimum_output_root: String,
    pub surplus_commitment_root: String,
    pub total_surplus_amount: u64,
    pub clearing_price_numerator: u64,
    pub clearing_price_denominator: u64,
    pub pool_curve: String,
    pub solver_bid_id: String,
    pub clearing_price_commitment_root: String,
    pub aggregate_surplus_commitment_root: String,
    pub authorization: Authorization,
}

impl SealedSwapSettlementReceipt {
    pub fn expected_clearing_price_commitment_root(&self) -> String {
        sealed_swap_clearing_price_commitment_root(
            &self.pool_id,
            &self.route_commitment,
            &self.asset_in_id,
            &self.asset_out_id,
            self.total_amount_in,
            self.total_amount_out,
            self.clearing_price_numerator,
            self.clearing_price_denominator,
            &self.pool_curve,
        )
    }

    pub fn expected_aggregate_surplus_commitment_root(&self) -> String {
        sealed_swap_aggregate_surplus_commitment_root(
            self.intent_count,
            &self.intent_root,
            &self.surplus_commitment_root,
            self.total_surplus_amount,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "sealed_swap_settlement_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "block_height": self.block_height,
            "tx_public_hash": self.tx_public_hash,
            "pool_id": self.pool_id,
            "solver_label": self.solver_label,
            "intent_count": self.intent_count,
            "intent_root": self.intent_root,
            "route_commitment": self.route_commitment,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "total_amount_in": self.total_amount_in,
            "total_amount_out": self.total_amount_out,
            "network_fee_total": self.network_fee_total,
            "pool_fee_bps": self.pool_fee_bps,
            "pool_curve": self.pool_curve,
            "pool_before_root": self.pool_before_root,
            "pool_after_root": self.pool_after_root,
            "pool_before_reserve_in": self.pool_before_reserve_in,
            "pool_before_reserve_out": self.pool_before_reserve_out,
            "pool_after_reserve_in": self.pool_after_reserve_in,
            "pool_after_reserve_out": self.pool_after_reserve_out,
            "fill_commitment_root": self.fill_commitment_root,
            "minimum_output_root": self.minimum_output_root,
            "surplus_commitment_root": self.surplus_commitment_root,
            "total_surplus_amount": self.total_surplus_amount,
            "clearing_price_numerator": self.clearing_price_numerator,
            "clearing_price_denominator": self.clearing_price_denominator,
            "clearing_price_commitment_root": self.clearing_price_commitment_root,
            "aggregate_surplus_commitment_root": self.aggregate_surplus_commitment_root,
            "solver_bid_id": self.solver_bid_id,
        })
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(), &self.authorization)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmRouteSwap {
    pub pool_ids: Vec<String>,
    pub spent_note_id: String,
    pub nullifier: String,
    pub asset_path: Vec<String>,
    pub hop_amounts: Vec<u64>,
    pub amount_in: u64,
    pub amount_out: u64,
    pub output_notes: Vec<Note>,
    pub network_fee: u64,
    pub encrypted_payload_hash: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl AmmRouteSwap {
    pub fn asset_in_id(&self) -> String {
        self.asset_path.first().cloned().unwrap_or_default()
    }

    pub fn asset_out_id(&self) -> String {
        self.asset_path.last().cloned().unwrap_or_default()
    }

    pub fn route_root(&self) -> String {
        let leaves = self
            .pool_ids
            .iter()
            .zip(self.asset_path.windows(2))
            .zip(self.hop_amounts.iter())
            .map(|((pool_id, assets), amount_out)| {
                json!({
                    "pool_id": pool_id,
                    "asset_in_id": assets[0],
                    "asset_out_id": assets[1],
                    "amount_out": amount_out,
                })
            })
            .collect::<Vec<_>>();
        merkle_root("AMM-ROUTE-HOP", &leaves)
    }

    pub fn unsigned_record(&self, include_spent_note: bool) -> Value {
        let mut record = json!({
            "kind": "amm_route_swap",
            "pool_ids": self.pool_ids,
            "route_hop_count": self.pool_ids.len(),
            "route_root": self.route_root(),
            "nullifier": self.nullifier,
            "asset_path": self.asset_path,
            "hop_amounts": self.hop_amounts,
            "asset_in_id": self.asset_in_id(),
            "asset_out_id": self.asset_out_id(),
            "amount_in": self.amount_in,
            "amount_out": self.amount_out,
            "output_commitments": output_commitments(&self.output_notes),
            "network_fee": self.network_fee,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_note {
            record
                .as_object_mut()
                .expect("AMM route swap record object")
                .insert(
                    "spent_note_id".to_string(),
                    Value::String(self.spent_note_id.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(false), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record
            .as_object_mut()
            .expect("AMM route swap state record object");
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkPoolSwap {
    pub spent_note_a_id: String,
    pub spent_note_b_id: String,
    pub nullifier_a: String,
    pub nullifier_b: String,
    pub asset_a_id: String,
    pub asset_b_id: String,
    pub amount_a: u64,
    pub amount_b: u64,
    pub recipient_a_view_key: String,
    pub recipient_b_view_key: String,
    pub network_fee_a: u64,
    pub network_fee_b: u64,
    pub match_salt: String,
    pub output_notes: Vec<Note>,
    pub encrypted_payload_hash: String,
    pub signer_a_label: String,
    pub signer_b_label: String,
    pub authorization_a: Authorization,
    pub authorization_b: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl DarkPoolSwap {
    pub fn trade_commitment(&self) -> String {
        domain_hash(
            "DARK-POOL-SWAP-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.asset_a_id),
                HashPart::Str(&self.asset_b_id),
                HashPart::Int(self.amount_a as i128),
                HashPart::Int(self.amount_b as i128),
                HashPart::Int(self.network_fee_a as i128),
                HashPart::Int(self.network_fee_b as i128),
                HashPart::Str(&dark_pool_recipient_a_commitment(
                    &self.recipient_a_view_key,
                )),
                HashPart::Str(&dark_pool_recipient_b_commitment(
                    &self.recipient_b_view_key,
                )),
                HashPart::Str(&self.match_salt),
            ],
            32,
        )
    }

    pub fn leg_authorization_payload(&self, side: &str) -> DefiResult<Value> {
        let (
            spent_note_id,
            nullifier,
            asset_in_id,
            asset_out_id,
            amount_in,
            amount_out,
            network_fee,
        ) = match side {
            "a" => (
                &self.spent_note_a_id,
                &self.nullifier_a,
                &self.asset_a_id,
                &self.asset_b_id,
                self.amount_a,
                self.amount_b,
                self.network_fee_a,
            ),
            "b" => (
                &self.spent_note_b_id,
                &self.nullifier_b,
                &self.asset_b_id,
                &self.asset_a_id,
                self.amount_b,
                self.amount_a,
                self.network_fee_b,
            ),
            _ => return Err("dark pool leg must be a or b".to_string()),
        };
        Ok(json!({
            "kind": "dark_pool_swap",
            "chain_id": CHAIN_ID,
            "side": side,
            "trade_commitment": self.trade_commitment(),
            "spent_note_id": spent_note_id,
            "nullifier": nullifier,
            "asset_in_id": asset_in_id,
            "asset_out_id": asset_out_id,
            "amount_in": amount_in,
            "amount_out": amount_out,
            "network_fee": network_fee,
            "output_commitments": output_commitments(&self.output_notes),
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_system": self.proof_system,
        }))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dark_pool_swap",
            "trade_commitment": self.trade_commitment(),
            "nullifier_a": self.nullifier_a,
            "nullifier_b": self.nullifier_b,
            "output_commitments": output_commitments(&self.output_notes),
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
            "auth_a_scheme": self.authorization_a.auth_scheme,
            "auth_a_public_key": self.authorization_a.auth_public_key,
            "auth_a_transcript_hash": self.authorization_a.auth_transcript_hash,
            "auth_a_signature": self.authorization_a.auth_signature,
            "auth_b_scheme": self.authorization_b.auth_scheme,
            "auth_b_public_key": self.authorization_b.auth_public_key,
            "auth_b_transcript_hash": self.authorization_b.auth_transcript_hash,
            "auth_b_signature": self.authorization_b.auth_signature,
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "kind": "dark_pool_swap",
            "spent_note_a_id": self.spent_note_a_id,
            "spent_note_b_id": self.spent_note_b_id,
            "nullifier_a": self.nullifier_a,
            "nullifier_b": self.nullifier_b,
            "asset_a_id": self.asset_a_id,
            "asset_b_id": self.asset_b_id,
            "amount_a": self.amount_a,
            "amount_b": self.amount_b,
            "recipient_a_view_key": self.recipient_a_view_key,
            "recipient_b_view_key": self.recipient_b_view_key,
            "network_fee_a": self.network_fee_a,
            "network_fee_b": self.network_fee_b,
            "match_salt": self.match_salt,
            "output_notes": self.output_notes.iter().map(Note::state_record).collect::<Vec<_>>(),
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "signer_a_label": self.signer_a_label,
            "signer_b_label": self.signer_b_label,
            "auth_a_scheme": self.authorization_a.auth_scheme,
            "auth_a_public_key": self.authorization_a.auth_public_key,
            "auth_a_transcript_hash": self.authorization_a.auth_transcript_hash,
            "auth_a_signature": self.authorization_a.auth_signature,
            "auth_b_scheme": self.authorization_b.auth_scheme,
            "auth_b_public_key": self.authorization_b.auth_public_key,
            "auth_b_transcript_hash": self.authorization_b.auth_transcript_hash,
            "auth_b_signature": self.authorization_b.auth_signature,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.state_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSwapOrderCommitment {
    pub commitment_id: String,
    pub pool_id: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub order_commitment: String,
    pub owner_commitment: String,
    pub min_reveal_height: u64,
    pub expires_height: u64,
    pub status: String,
    pub revealed_intent_hash: String,
    pub revealed_at_height: u64,
    pub signer_label: String,
    pub authorization: Authorization,
}

impl SealedSwapOrderCommitment {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "sealed_swap_order_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "pool_id": self.pool_id,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "order_commitment": self.order_commitment,
            "owner_commitment": self.owner_commitment,
            "min_reveal_height": self.min_reveal_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("sealed swap commitment record object");
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "revealed_intent_hash".to_string(),
            Value::String(self.revealed_intent_hash.clone()),
        );
        object.insert(
            "revealed_at_height".to_string(),
            Value::from(self.revealed_at_height),
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

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("sealed swap commitment state object")
            .insert(
                "signer_label".to_string(),
                Value::String(self.signer_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSwapSolverBid {
    pub bid_id: String,
    pub pool_id: String,
    pub solver_label: String,
    pub batch_commitment_root: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub total_amount_in: u64,
    pub quoted_amount_out: u64,
    pub network_fee_total: u64,
    pub expires_height: u64,
    pub status: String,
    pub settled_tx_public_hash: String,
    pub settled_at_height: u64,
    pub authorization: Authorization,
}

impl SealedSwapSolverBid {
    pub fn solver_commitment(&self) -> String {
        sealed_swap_solver_commitment(&self.solver_label)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "sealed_swap_solver_bid",
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "pool_id": self.pool_id,
            "solver_label": self.solver_label,
            "solver_commitment": self.solver_commitment(),
            "batch_commitment_root": self.batch_commitment_root,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "total_amount_in": self.total_amount_in,
            "quoted_amount_out": self.quoted_amount_out,
            "network_fee_total": self.network_fee_total,
            "expires_height": self.expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("sealed swap solver bid record object");
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "settled_tx_public_hash".to_string(),
            Value::String(self.settled_tx_public_hash.clone()),
        );
        object.insert(
            "settled_at_height".to_string(),
            Value::from(self.settled_at_height),
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
}

pub fn fee_market_resource_for_asset_mint(tx: &AssetMint) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 90,
        privacy_proof_count: 0,
        contract_call_count: 0,
        observed_fee_units: 0,
        estimated_proof_bytes: 0,
        authorization_count: 1,
        fee_asset_ids: vec![tx.asset_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "asset_mint".to_string()),
            ("asset".to_string(), tx.asset_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_asset_burn(tx: &AssetBurn) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 140 + (tx.output_notes.len() as u64) * 16,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: 0,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids: vec![tx.asset_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "asset_burn".to_string()),
            ("asset".to_string(), tx.asset_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_amm_liquidity_add(tx: &AmmLiquidityAdd) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 420 + (tx.output_notes.len() as u64) * 30,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.network_fee,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids: Vec::new(),
        fee_lanes: vec![
            ("operation".to_string(), "amm_liquidity_add".to_string()),
            ("amm_pool".to_string(), tx.pool_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_amm_swap(tx: &AmmSwap) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 360 + (tx.output_notes.len() as u64) * 25,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.network_fee,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids: vec![tx.asset_in_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "amm_swap".to_string()),
            ("amm_pool".to_string(), tx.pool_id.clone()),
            ("fee_asset".to_string(), tx.asset_in_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_amm_batch_swap(tx: &AmmBatchSwap) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 420 + (tx.spent_note_ids.len() as u64) * 35 + 50,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.network_fee,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES
            + tx.spent_note_ids.len().saturating_sub(1) as u64 * 512,
        authorization_count: 1,
        fee_asset_ids: vec![tx.asset_in_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "amm_batch_swap".to_string()),
            ("amm_pool".to_string(), tx.pool_id.clone()),
            ("fee_asset".to_string(), tx.asset_in_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_amm_sealed_batch_swap(tx: &AmmSealedBatchSwap) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 480 + (tx.fills.len() as u64) * 70 + 50,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.network_fee_total,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES
            + tx.fills.len().saturating_sub(1) as u64 * 768,
        authorization_count: tx.fills.len() as u64,
        fee_asset_ids: vec![tx.asset_in_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "sealed_amm_batch_swap".to_string()),
            ("amm_pool".to_string(), tx.pool_id.clone()),
            ("commitment_root".to_string(), tx.commitment_root()),
            ("fee_asset".to_string(), tx.asset_in_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_amm_route_swap(tx: &AmmRouteSwap) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 420 + (tx.pool_ids.len() as u64) * 90 + 50,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.network_fee,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES
            + tx.pool_ids.len().saturating_sub(1) as u64 * 384,
        authorization_count: 1,
        fee_asset_ids: vec![tx.asset_in_id()],
        fee_lanes: vec![
            ("operation".to_string(), "amm_route_swap".to_string()),
            ("route_root".to_string(), tx.route_root()),
            ("fee_asset".to_string(), tx.asset_in_id()),
        ],
    }
}

pub fn fee_market_resource_for_dark_pool_swap(tx: &DarkPoolSwap) -> FeeMarketResource {
    let mut fee_asset_ids = vec![tx.asset_a_id.clone(), tx.asset_b_id.clone()];
    fee_asset_ids.sort();
    fee_asset_ids.dedup();
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 520,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.network_fee_a + tx.network_fee_b,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES + 512,
        authorization_count: 2,
        fee_asset_ids,
        fee_lanes: vec![
            ("operation".to_string(), "dark_pool_swap".to_string()),
            (
                "asset_pair".to_string(),
                dark_pool_asset_pair_commitment(&tx.asset_a_id, &tx.asset_b_id),
            ),
        ],
    }
}

pub fn fee_market_resource_for_lending_borrow(tx: &LendingBorrow) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 360 + (tx.output_notes.len() as u64) * 24,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.borrow_fee,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids: Vec::new(),
        fee_lanes: vec![
            ("operation".to_string(), "lending_borrow".to_string()),
            ("lending_market".to_string(), tx.market_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_lending_repay(tx: &LendingRepay) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 300 + (tx.output_notes.len() as u64) * 20,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.repay_fee,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids: Vec::new(),
        fee_lanes: vec![
            ("operation".to_string(), "lending_repay".to_string()),
            ("lending_position".to_string(), tx.position_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_lending_liquidation(tx: &LendingLiquidation) -> FeeMarketResource {
    FeeMarketResource {
        public_record: tx.public_record(),
        execution_fuel: 340 + (tx.output_notes.len() as u64) * 20,
        privacy_proof_count: 1,
        contract_call_count: 0,
        observed_fee_units: tx.liquidation_fee,
        estimated_proof_bytes: crate::DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids: Vec::new(),
        fee_lanes: vec![
            ("operation".to_string(), "lending_liquidation".to_string()),
            ("lending_position".to_string(), tx.position_id.clone()),
        ],
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePriceAttestation {
    pub publisher_label: String,
    pub authorization: Authorization,
}

impl OraclePriceAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "publisher_label": self.publisher_label,
            "auth_scheme": self.authorization.auth_scheme,
            "auth_public_key": self.authorization.auth_public_key,
            "auth_transcript_hash": self.authorization.auth_transcript_hash,
            "auth_signature": self.authorization.auth_signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePriceFeed {
    pub feed_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub price_numerator: u64,
    pub price_denominator: u64,
    pub confidence_bps: u64,
    pub round_id: u64,
    pub published_at_height: u64,
    pub attestations: Vec<OraclePriceAttestation>,
}

impl OraclePriceFeed {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "price_numerator": self.price_numerator,
            "price_denominator": self.price_denominator,
            "confidence_bps": self.confidence_bps,
            "round_id": self.round_id,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "ORACLE-PRICE-ATTESTATION",
            &self
                .attestations
                .iter()
                .map(OraclePriceAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "price_numerator": self.price_numerator,
            "price_denominator": self.price_denominator,
            "confidence_bps": self.confidence_bps,
            "round_id": self.round_id,
            "published_at_height": self.published_at_height,
            "attestation_root": self.attestation_root(),
            "attestation_count": self.attestations.len(),
            "attestations": self.attestations.iter().map(OraclePriceAttestation::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingMarket {
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub oracle_feed_id: String,
    pub total_collateral: u64,
    pub total_debt: u64,
    pub status: String,
}

impl LendingMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "oracle_feed_id": self.oracle_feed_id,
            "total_collateral": self.total_collateral,
            "total_debt": self.total_debt,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingPosition {
    pub position_id: String,
    pub market_id: String,
    pub owner_view_key: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_amount: u64,
    pub debt_amount: u64,
    pub collateral_commitment: String,
    pub debt_commitment: String,
    pub status: String,
    pub created_at_height: u64,
    pub closed_at_height: u64,
}

impl LendingPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "market_id": self.market_id,
            "owner_commitment": lending_owner_commitment(&self.owner_view_key),
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "collateral_commitment": self.collateral_commitment,
            "debt_commitment": self.debt_commitment,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "closed_at_height": self.closed_at_height,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("lending position state object");
        object.insert(
            "owner_view_key".to_string(),
            Value::String(self.owner_view_key.clone()),
        );
        object.insert(
            "collateral_amount".to_string(),
            json!(self.collateral_amount),
        );
        object.insert("debt_amount".to_string(), json!(self.debt_amount));
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingBorrow {
    pub market_id: String,
    pub spent_collateral_note_id: String,
    pub nullifier: String,
    pub collateral_amount: u64,
    pub borrow_amount: u64,
    pub borrow_fee: u64,
    pub position_id: String,
    pub output_notes: Vec<Note>,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl LendingBorrow {
    pub fn terms_hash(&self) -> String {
        lending_borrow_terms_hash(
            &self.market_id,
            self.collateral_amount,
            self.borrow_amount,
            self.borrow_fee,
        )
    }

    pub fn unsigned_record(&self, include_spent_note: bool) -> Value {
        let mut record = json!({
            "kind": "lending_borrow",
            "market_id": self.market_id,
            "nullifier": self.nullifier,
            "position_id": self.position_id,
            "terms_hash": self.terms_hash(),
            "output_commitments": output_commitments(&self.output_notes),
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_note {
            record
                .as_object_mut()
                .expect("lending borrow object")
                .insert(
                    "spent_collateral_note_id".to_string(),
                    Value::String(self.spent_collateral_note_id.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(false), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record.as_object_mut().expect("lending borrow state object");
        object.insert(
            "collateral_amount".to_string(),
            json!(self.collateral_amount),
        );
        object.insert("borrow_amount".to_string(), json!(self.borrow_amount));
        object.insert("borrow_fee".to_string(), json!(self.borrow_fee));
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingRepay {
    pub position_id: String,
    pub spent_debt_note_id: String,
    pub nullifier: String,
    pub repay_fee: u64,
    pub output_notes: Vec<Note>,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl LendingRepay {
    pub fn terms_hash(&self) -> String {
        lending_repay_terms_hash(
            self.position_id.as_str(),
            self.repay_fee,
            &self.output_notes,
        )
    }

    pub fn unsigned_record(&self, include_spent_note: bool) -> Value {
        let mut record = json!({
            "kind": "lending_repay",
            "position_id": self.position_id,
            "nullifier": self.nullifier,
            "terms_hash": self.terms_hash(),
            "output_commitments": output_commitments(&self.output_notes),
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_note {
            record
                .as_object_mut()
                .expect("lending repay object")
                .insert(
                    "spent_debt_note_id".to_string(),
                    Value::String(self.spent_debt_note_id.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(false), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record.as_object_mut().expect("lending repay state object");
        object.insert("repay_fee".to_string(), json!(self.repay_fee));
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingLiquidation {
    pub position_id: String,
    pub spent_debt_note_id: String,
    pub nullifier: String,
    pub liquidation_fee: u64,
    pub liquidator_view_key: String,
    pub output_notes: Vec<Note>,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: PrivacyProof,
}

impl LendingLiquidation {
    pub fn liquidator_commitment(&self) -> String {
        lending_liquidator_commitment(&self.liquidator_view_key)
    }

    pub fn terms_hash(&self) -> String {
        lending_liquidation_terms_hash(
            &self.position_id,
            self.liquidation_fee,
            &self.liquidator_commitment(),
            &self.output_notes,
        )
    }

    pub fn unsigned_record(&self, include_spent_note: bool) -> Value {
        let mut record = json!({
            "kind": "lending_liquidation",
            "position_id": self.position_id,
            "nullifier": self.nullifier,
            "liquidator_commitment": self.liquidator_commitment(),
            "terms_hash": self.terms_hash(),
            "output_commitments": output_commitments(&self.output_notes),
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.public_record(),
        });
        if include_spent_note {
            record
                .as_object_mut()
                .expect("lending liquidation object")
                .insert(
                    "spent_debt_note_id".to_string(),
                    Value::String(self.spent_debt_note_id.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(false), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = signed_public_record(self.unsigned_record(true), &self.authorization);
        let object = record
            .as_object_mut()
            .expect("lending liquidation state object");
        object.insert("liquidation_fee".to_string(), json!(self.liquidation_fee));
        object.insert(
            "liquidator_view_key".to_string(),
            Value::String(self.liquidator_view_key.clone()),
        );
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof.state_record(),
        );
        record
    }
}

fn signed_public_record(mut record: Value, authorization: &Authorization) -> Value {
    let object = record.as_object_mut().expect("signed record object");
    object.insert(
        "auth_scheme".to_string(),
        Value::String(authorization.auth_scheme.clone()),
    );
    object.insert(
        "auth_public_key".to_string(),
        Value::String(authorization.auth_public_key.clone()),
    );
    object.insert(
        "auth_transcript_hash".to_string(),
        Value::String(authorization.auth_transcript_hash.clone()),
    );
    object.insert(
        "auth_signature".to_string(),
        Value::String(authorization.auth_signature.clone()),
    );
    record
}

fn empty_authorization() -> Authorization {
    Authorization {
        signer_label: String::new(),
        auth_scheme: String::new(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefiStagedTx {
    AssetMint(AssetMint),
    AssetBurn(AssetBurn),
    AmmLiquidityAdd(AmmLiquidityAdd),
    AmmSwap(AmmSwap),
    AmmBatchSwap(AmmBatchSwap),
    AmmRouteSwap(AmmRouteSwap),
    DarkPoolSwap(DarkPoolSwap),
    AmmSealedBatchSwap(AmmSealedBatchSwap),
    LendingBorrow(LendingBorrow),
    LendingRepay(LendingRepay),
    LendingLiquidation(LendingLiquidation),
}

impl DefiStagedTx {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AssetMint(_) => "asset_mint",
            Self::AssetBurn(_) => "asset_burn",
            Self::AmmLiquidityAdd(_) => "amm_liquidity_add",
            Self::AmmSwap(_) => "amm_swap",
            Self::AmmBatchSwap(_) => "amm_batch_swap",
            Self::AmmRouteSwap(_) => "amm_route_swap",
            Self::DarkPoolSwap(_) => "dark_pool_swap",
            Self::AmmSealedBatchSwap(_) => "sealed_amm_batch_swap",
            Self::LendingBorrow(_) => "lending_borrow",
            Self::LendingRepay(_) => "lending_repay",
            Self::LendingLiquidation(_) => "lending_liquidation",
        }
    }

    pub fn public_record(&self) -> Value {
        match self {
            Self::AssetMint(tx) => tx.public_record(),
            Self::AssetBurn(tx) => tx.public_record(),
            Self::AmmLiquidityAdd(tx) => tx.public_record(),
            Self::AmmSwap(tx) => tx.public_record(),
            Self::AmmBatchSwap(tx) => tx.public_record(),
            Self::AmmRouteSwap(tx) => tx.public_record(),
            Self::DarkPoolSwap(tx) => tx.public_record(),
            Self::AmmSealedBatchSwap(tx) => tx.public_record(),
            Self::LendingBorrow(tx) => tx.public_record(),
            Self::LendingRepay(tx) => tx.public_record(),
            Self::LendingLiquidation(tx) => tx.public_record(),
        }
    }

    pub fn state_record(&self) -> Value {
        match self {
            Self::AssetMint(tx) => tx.state_record(),
            Self::AssetBurn(tx) => tx.state_record(),
            Self::AmmLiquidityAdd(tx) => tx.state_record(),
            Self::AmmSwap(tx) => tx.state_record(),
            Self::AmmBatchSwap(tx) => tx.state_record(),
            Self::AmmRouteSwap(tx) => tx.state_record(),
            Self::DarkPoolSwap(tx) => tx.state_record(),
            Self::AmmSealedBatchSwap(tx) => tx.state_record(),
            Self::LendingBorrow(tx) => tx.state_record(),
            Self::LendingRepay(tx) => tx.state_record(),
            Self::LendingLiquidation(tx) => tx.state_record(),
        }
    }

    pub fn fee_resource(&self) -> FeeMarketResource {
        match self {
            Self::AssetMint(tx) => fee_market_resource_for_asset_mint(tx),
            Self::AssetBurn(tx) => fee_market_resource_for_asset_burn(tx),
            Self::AmmLiquidityAdd(tx) => fee_market_resource_for_amm_liquidity_add(tx),
            Self::AmmSwap(tx) => fee_market_resource_for_amm_swap(tx),
            Self::AmmBatchSwap(tx) => fee_market_resource_for_amm_batch_swap(tx),
            Self::AmmRouteSwap(tx) => fee_market_resource_for_amm_route_swap(tx),
            Self::DarkPoolSwap(tx) => fee_market_resource_for_dark_pool_swap(tx),
            Self::AmmSealedBatchSwap(tx) => fee_market_resource_for_amm_sealed_batch_swap(tx),
            Self::LendingBorrow(tx) => fee_market_resource_for_lending_borrow(tx),
            Self::LendingRepay(tx) => fee_market_resource_for_lending_repay(tx),
            Self::LendingLiquidation(tx) => fee_market_resource_for_lending_liquidation(tx),
        }
    }

    pub fn spent_note_ids(&self) -> Vec<String> {
        match self {
            Self::AssetMint(_) => Vec::new(),
            Self::AssetBurn(tx) => vec![tx.spent_note_id.clone()],
            Self::AmmLiquidityAdd(tx) => {
                vec![tx.spent_note_a_id.clone(), tx.spent_note_b_id.clone()]
            }
            Self::AmmSwap(tx) => vec![tx.spent_note_id.clone()],
            Self::AmmBatchSwap(tx) => tx.spent_note_ids.clone(),
            Self::AmmRouteSwap(tx) => vec![tx.spent_note_id.clone()],
            Self::DarkPoolSwap(tx) => {
                vec![tx.spent_note_a_id.clone(), tx.spent_note_b_id.clone()]
            }
            Self::AmmSealedBatchSwap(tx) => tx
                .fills
                .iter()
                .map(|fill| fill.intent.spent_note_id.clone())
                .collect(),
            Self::LendingBorrow(tx) => vec![tx.spent_collateral_note_id.clone()],
            Self::LendingRepay(tx) => vec![tx.spent_debt_note_id.clone()],
            Self::LendingLiquidation(tx) => vec![tx.spent_debt_note_id.clone()],
        }
    }

    pub fn spent_nullifiers(&self) -> Vec<String> {
        match self {
            Self::AssetMint(_) => Vec::new(),
            Self::AssetBurn(tx) => vec![tx.nullifier.clone()],
            Self::AmmLiquidityAdd(tx) => vec![tx.nullifier_a.clone(), tx.nullifier_b.clone()],
            Self::AmmSwap(tx) => vec![tx.nullifier.clone()],
            Self::AmmBatchSwap(tx) => tx.nullifiers.clone(),
            Self::AmmRouteSwap(tx) => vec![tx.nullifier.clone()],
            Self::DarkPoolSwap(tx) => vec![tx.nullifier_a.clone(), tx.nullifier_b.clone()],
            Self::AmmSealedBatchSwap(tx) => tx
                .fills
                .iter()
                .map(|fill| fill.intent.nullifier.clone())
                .collect(),
            Self::LendingBorrow(tx) => vec![tx.nullifier.clone()],
            Self::LendingRepay(tx) => vec![tx.nullifier.clone()],
            Self::LendingLiquidation(tx) => vec![tx.nullifier.clone()],
        }
    }

    pub fn output_notes(&self) -> Vec<Note> {
        match self {
            Self::AssetMint(tx) => vec![tx.output_note.clone()],
            Self::AssetBurn(tx) => tx.output_notes.clone(),
            Self::AmmLiquidityAdd(tx) => tx.output_notes.clone(),
            Self::AmmSwap(tx) => tx.output_notes.clone(),
            Self::AmmBatchSwap(tx) => tx.output_notes.clone(),
            Self::AmmRouteSwap(tx) => tx.output_notes.clone(),
            Self::DarkPoolSwap(tx) => tx.output_notes.clone(),
            Self::AmmSealedBatchSwap(tx) => tx.output_notes(),
            Self::LendingBorrow(tx) => tx.output_notes.clone(),
            Self::LendingRepay(tx) => tx.output_notes.clone(),
            Self::LendingLiquidation(tx) => tx.output_notes.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiApplyOutcome {
    pub public_record: Value,
    pub state_record: Value,
    pub fee_resource: FeeMarketResource,
    pub spent_note_ids: Vec<String>,
    pub spent_nullifiers: Vec<String>,
    pub output_notes: Vec<Note>,
    pub sealed_swap_receipt: Option<SealedSwapSettlementReceipt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiState {
    pub assets: BTreeMap<String, Asset>,
    pub asset_supplies: BTreeMap<String, AssetSupply>,
    pub notes: BTreeMap<String, Note>,
    pub pools: BTreeMap<String, AmmPool>,
    pub oracle_prices: BTreeMap<String, OraclePriceFeed>,
    pub lending_markets: BTreeMap<String, LendingMarket>,
    pub lending_positions: BTreeMap<String, LendingPosition>,
    pub sealed_swap_order_commitments: BTreeMap<String, SealedSwapOrderCommitment>,
    pub sealed_swap_solver_bids: BTreeMap<String, SealedSwapSolverBid>,
    pub sealed_swap_settlement_receipts: BTreeMap<String, SealedSwapSettlementReceipt>,
    pub spent_nullifiers: Vec<String>,
    pub fees_collected: BTreeMap<String, u64>,
    pub nonce: u64,
    pub height: u64,
}

impl DefiState {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_nonce(&mut self) -> u64 {
        self.nonce += 1;
        self.nonce
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> DefiResult<u64> {
        self.height = self
            .height
            .checked_add(blocks)
            .ok_or_else(|| "defi state height overflow".to_string())?;
        Ok(self.height)
    }

    pub fn set_nonce_floor(&mut self, nonce_floor: u64) {
        self.nonce = self.nonce.max(nonce_floor);
    }

    pub fn apply_staged_tx(&mut self, tx: &DefiStagedTx) -> DefiResult<DefiApplyOutcome> {
        let public_record = tx.public_record();
        let state_record = tx.state_record();
        let fee_resource = tx.fee_resource();
        let spent_note_ids = tx.spent_note_ids();
        let spent_nullifiers = tx.spent_nullifiers();
        let output_notes = tx.output_notes();
        let sealed_swap_receipt = match tx {
            DefiStagedTx::AssetMint(tx) => {
                self.apply_staged_asset_mint(tx)?;
                None
            }
            DefiStagedTx::AssetBurn(tx) => {
                self.apply_staged_asset_burn(tx)?;
                None
            }
            DefiStagedTx::AmmLiquidityAdd(tx) => {
                self.apply_staged_amm_liquidity_add(tx)?;
                None
            }
            DefiStagedTx::AmmSwap(tx) => {
                self.apply_staged_amm_swap(tx)?;
                None
            }
            DefiStagedTx::AmmBatchSwap(tx) => {
                self.apply_staged_amm_batch_swap(tx)?;
                None
            }
            DefiStagedTx::AmmRouteSwap(tx) => {
                self.apply_staged_amm_route_swap(tx)?;
                None
            }
            DefiStagedTx::DarkPoolSwap(tx) => {
                self.apply_staged_dark_pool_swap(tx)?;
                None
            }
            DefiStagedTx::AmmSealedBatchSwap(tx) => {
                Some(self.apply_staged_amm_sealed_batch_swap(tx)?)
            }
            DefiStagedTx::LendingBorrow(tx) => {
                self.apply_staged_lending_borrow(tx)?;
                None
            }
            DefiStagedTx::LendingRepay(tx) => {
                self.apply_staged_lending_repay(tx)?;
                None
            }
            DefiStagedTx::LendingLiquidation(tx) => {
                self.apply_staged_lending_liquidation(tx)?;
                None
            }
        };
        self.set_nonce_floor(self.nonce + output_notes.len() as u64);
        Ok(DefiApplyOutcome {
            public_record,
            state_record,
            fee_resource,
            spent_note_ids,
            spent_nullifiers,
            output_notes,
            sealed_swap_receipt,
        })
    }

    fn apply_staged_asset_mint(&mut self, tx: &AssetMint) -> DefiResult<()> {
        let asset = self.require_asset(&tx.asset_id)?.clone();
        if !asset_supports_native_mint_burn(&asset) {
            return Err("asset does not support native mint-burn".to_string());
        }
        if tx.amount == 0 || tx.output_note.amount != tx.amount {
            return Err("staged asset mint amount mismatch".to_string());
        }
        if tx.output_note.asset_id != tx.asset_id {
            return Err("staged asset mint output asset mismatch".to_string());
        }
        self.enforce_asset_mint_cap(&asset, tx.amount)?;
        if tx.signer_label != asset_issuer_label(&asset) {
            return Err("asset mint signer does not match issuer policy".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "asset_mint",
            &tx.unsigned_record(),
            &tx.authorization,
        ) {
            return Err("invalid asset mint authorization".to_string());
        }
        self.insert_staged_output_notes(std::slice::from_ref(&tx.output_note))?;
        self.update_asset_supply(&tx.asset_id, tx.amount, 0)
    }

    fn apply_staged_asset_burn(&mut self, tx: &AssetBurn) -> DefiResult<()> {
        let spent = self.remove_staged_note(&tx.spent_note_id, &tx.nullifier)?;
        if spent.asset_id != tx.asset_id || tx.amount == 0 || tx.amount > spent.amount {
            return Err("staged asset burn amount or asset mismatch".to_string());
        }
        let asset = self.require_asset(&tx.asset_id)?.clone();
        if !asset_supports_native_mint_burn(&asset) {
            return Err("asset does not support native mint-burn".to_string());
        }
        if tx.signer_label != spent.owner_view_key {
            return Err("staged asset burn signer mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "asset_burn",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid asset burn authorization".to_string());
        }
        let change_total = tx.output_notes.iter().try_fold(0_u64, |total, note| {
            if note.asset_id != tx.asset_id {
                return Err("staged asset burn output asset mismatch".to_string());
            }
            total
                .checked_add(note.amount)
                .ok_or_else(|| "staged asset burn output overflow".to_string())
        })?;
        if change_total != spent.amount - tx.amount {
            return Err("staged asset burn change mismatch".to_string());
        }
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.insert_staged_output_notes(&tx.output_notes)?;
        self.update_asset_supply(&tx.asset_id, 0, tx.amount)
    }

    fn apply_staged_amm_liquidity_add(&mut self, tx: &AmmLiquidityAdd) -> DefiResult<()> {
        let pool = self.require_pool(&tx.pool_id)?.clone();
        let note_a = self.remove_staged_note(&tx.spent_note_a_id, &tx.nullifier_a)?;
        let note_b = self.remove_staged_note(&tx.spent_note_b_id, &tx.nullifier_b)?;
        if note_a.asset_id != pool.asset_a_id || note_b.asset_id != pool.asset_b_id {
            return Err("staged liquidity notes do not match pool assets".to_string());
        }
        if tx.signer_label != note_a.owner_view_key || tx.signer_label != note_b.owner_view_key {
            return Err("staged liquidity signer mismatch".to_string());
        }
        if note_a.amount < tx.amount_a + tx.network_fee || note_b.amount < tx.amount_b {
            return Err("staged liquidity note amount mismatch".to_string());
        }
        if amm_lp_minted(&pool, tx.amount_a, tx.amount_b)? != tx.lp_minted {
            return Err("staged liquidity LP amount mismatch".to_string());
        }
        if tx
            .output_notes
            .first()
            .is_none_or(|note| note.asset_id != pool.lp_asset_id || note.amount != tx.lp_minted)
        {
            return Err("staged liquidity LP output mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "amm_liquidity_add",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid AMM liquidity authorization".to_string());
        }
        self.spent_nullifiers.push(tx.nullifier_a.clone());
        self.spent_nullifiers.push(tx.nullifier_b.clone());
        self.add_fee(&pool.asset_a_id, tx.network_fee);
        self.pools.insert(
            tx.pool_id.clone(),
            AmmPool {
                reserve_a: pool.reserve_a + tx.amount_a,
                reserve_b: pool.reserve_b + tx.amount_b,
                total_lp: pool.total_lp + tx.lp_minted,
                ..pool
            },
        );
        self.insert_staged_output_notes(&tx.output_notes)?;
        self.update_asset_supply(&tx.output_notes[0].asset_id, tx.lp_minted, 0)
    }

    fn apply_staged_amm_swap(&mut self, tx: &AmmSwap) -> DefiResult<()> {
        let pool = self.require_pool(&tx.pool_id)?.clone();
        let spent = self.remove_staged_note(&tx.spent_note_id, &tx.nullifier)?;
        if spent.asset_id != tx.asset_in_id || spent.amount < tx.amount_in + tx.network_fee {
            return Err("staged AMM swap input mismatch".to_string());
        }
        let (reserve_in, reserve_out, asset_out_id) = amm_asset_view(&pool, &tx.asset_in_id)?;
        if asset_out_id != tx.asset_out_id
            || amm_output_amount(&pool, reserve_in, reserve_out, tx.amount_in)? != tx.amount_out
        {
            return Err("staged AMM swap output mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "amm_swap",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid AMM swap authorization".to_string());
        }
        let updated_pool =
            updated_pool_for_swap(&pool, &tx.asset_in_id, tx.amount_in, tx.amount_out)?;
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&tx.asset_in_id, tx.network_fee);
        self.pools.insert(tx.pool_id.clone(), updated_pool);
        self.insert_staged_output_notes(&tx.output_notes)
    }

    fn apply_staged_amm_batch_swap(&mut self, tx: &AmmBatchSwap) -> DefiResult<()> {
        ensure_distinct(
            &tx.spent_note_ids,
            "staged batch swap notes must be distinct",
        )?;
        ensure_distinct(
            &tx.nullifiers,
            "staged batch swap nullifiers must be distinct",
        )?;
        if tx.spent_note_ids.len() != tx.nullifiers.len()
            || tx.spent_note_ids.len() != tx.amount_ins.len()
        {
            return Err("staged batch swap input length mismatch".to_string());
        }
        let pool = self.require_pool(&tx.pool_id)?.clone();
        let mut total_available = 0_u64;
        for ((note_id, nullifier), amount_in) in tx
            .spent_note_ids
            .iter()
            .zip(tx.nullifiers.iter())
            .zip(tx.amount_ins.iter())
        {
            let note = self.remove_staged_note(note_id, nullifier)?;
            if note.asset_id != tx.asset_in_id || note.amount < *amount_in {
                return Err("staged batch swap note mismatch".to_string());
            }
            total_available = total_available
                .checked_add(note.amount)
                .ok_or_else(|| "staged batch swap available overflow".to_string())?;
        }
        if total_available < tx.total_amount_in + tx.network_fee {
            return Err("staged batch swap fee coverage mismatch".to_string());
        }
        let (reserve_in, reserve_out, asset_out_id) = amm_asset_view(&pool, &tx.asset_in_id)?;
        if asset_out_id != tx.asset_out_id
            || amm_output_amount(&pool, reserve_in, reserve_out, tx.total_amount_in)?
                != tx.total_amount_out
        {
            return Err("staged batch swap output mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "amm_batch_swap",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid AMM batch swap authorization".to_string());
        }
        let updated_pool = updated_pool_for_swap(
            &pool,
            &tx.asset_in_id,
            tx.total_amount_in,
            tx.total_amount_out,
        )?;
        self.spent_nullifiers.extend(tx.nullifiers.iter().cloned());
        self.add_fee(&tx.asset_in_id, tx.network_fee);
        self.pools.insert(tx.pool_id.clone(), updated_pool);
        self.insert_staged_output_notes(&tx.output_notes)
    }

    fn apply_staged_amm_route_swap(&mut self, tx: &AmmRouteSwap) -> DefiResult<()> {
        let spent = self.remove_staged_note(&tx.spent_note_id, &tx.nullifier)?;
        if spent.asset_id != tx.asset_in_id() || spent.amount < tx.amount_in + tx.network_fee {
            return Err("staged route swap input mismatch".to_string());
        }
        let simulation = self.simulate_amm_route(&tx.pool_ids, &tx.asset_in_id(), tx.amount_in)?;
        if simulation.asset_path != tx.asset_path
            || simulation.hop_amounts != tx.hop_amounts
            || simulation.amount_out != tx.amount_out
        {
            return Err("staged route swap simulation mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "amm_route_swap",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid AMM route swap authorization".to_string());
        }
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&tx.asset_in_id(), tx.network_fee);
        for (pool_id, updated_pool) in simulation.updated_pools {
            self.pools.insert(pool_id, updated_pool);
        }
        self.insert_staged_output_notes(&tx.output_notes)
    }

    fn apply_staged_dark_pool_swap(&mut self, tx: &DarkPoolSwap) -> DefiResult<()> {
        let note_a = self.remove_staged_note(&tx.spent_note_a_id, &tx.nullifier_a)?;
        let note_b = self.remove_staged_note(&tx.spent_note_b_id, &tx.nullifier_b)?;
        if note_a.asset_id != tx.asset_a_id
            || note_b.asset_id != tx.asset_b_id
            || note_a.amount < tx.amount_a + tx.network_fee_a
            || note_b.amount < tx.amount_b + tx.network_fee_b
        {
            return Err("staged dark pool note mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_a_label,
            "dark_pool_swap",
            &tx.leg_authorization_payload("a")?,
            &tx.authorization_a,
        ) || !verify_authorization(
            &tx.signer_b_label,
            "dark_pool_swap",
            &tx.leg_authorization_payload("b")?,
            &tx.authorization_b,
        ) {
            return Err("invalid dark pool swap authorization".to_string());
        }
        self.spent_nullifiers.push(tx.nullifier_a.clone());
        self.spent_nullifiers.push(tx.nullifier_b.clone());
        self.add_fee(&tx.asset_a_id, tx.network_fee_a);
        self.add_fee(&tx.asset_b_id, tx.network_fee_b);
        self.insert_staged_output_notes(&tx.output_notes)
    }

    fn apply_staged_amm_sealed_batch_swap(
        &mut self,
        tx: &AmmSealedBatchSwap,
    ) -> DefiResult<SealedSwapSettlementReceipt> {
        let pool = self.require_pool(&tx.pool_id)?.clone();
        self.verify_amm_sealed_batch_swap(tx)?;
        let updated_pool = updated_pool_for_swap(
            &pool,
            &tx.asset_in_id,
            tx.total_amount_in,
            tx.total_amount_out,
        )?;
        let receipt = self.build_sealed_swap_settlement_receipt(tx, &pool, &updated_pool)?;
        for fill in &tx.fills {
            self.remove_staged_note(&fill.intent.spent_note_id, &fill.intent.nullifier)?;
            self.spent_nullifiers.push(fill.intent.nullifier.clone());
        }
        self.add_fee(&tx.asset_in_id, tx.network_fee_total);
        self.pools.insert(tx.pool_id.clone(), updated_pool.clone());
        self.insert_staged_output_notes(&tx.output_notes())?;
        self.mark_sealed_swap_commitments_revealed(tx)?;
        self.mark_sealed_swap_solver_bids_settled(tx)?;
        self.verify_sealed_swap_settlement_receipt(&receipt, tx, &pool, &updated_pool)?;
        self.sealed_swap_settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    fn apply_staged_lending_borrow(&mut self, tx: &LendingBorrow) -> DefiResult<()> {
        let market = self.require_lending_market(&tx.market_id)?.clone();
        let spent = self.remove_staged_note(&tx.spent_collateral_note_id, &tx.nullifier)?;
        if spent.asset_id != market.collateral_asset_id
            || spent.amount < tx.collateral_amount + tx.borrow_fee
            || tx.output_notes.first().is_none_or(|note| {
                note.asset_id != market.debt_asset_id || note.amount != tx.borrow_amount
            })
        {
            return Err("staged lending borrow mismatch".to_string());
        }
        if self.lending_positions.contains_key(&tx.position_id) {
            return Err("lending position already exists".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "lending_borrow",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid lending borrow authorization".to_string());
        }
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&market.collateral_asset_id, tx.borrow_fee);
        self.insert_staged_output_notes(&tx.output_notes)?;
        self.lending_positions.insert(
            tx.position_id.clone(),
            LendingPosition {
                position_id: tx.position_id.clone(),
                market_id: tx.market_id.clone(),
                owner_view_key: spent.owner_view_key,
                collateral_asset_id: market.collateral_asset_id.clone(),
                debt_asset_id: market.debt_asset_id.clone(),
                collateral_amount: tx.collateral_amount,
                debt_amount: tx.borrow_amount,
                collateral_commitment: spent.commitment,
                debt_commitment: tx.output_notes[0].commitment.clone(),
                status: "active".to_string(),
                created_at_height: self.height,
                closed_at_height: 0,
            },
        );
        self.bump_lending_market_totals(
            &tx.market_id,
            tx.collateral_amount as i128,
            tx.borrow_amount as i128,
        )
    }

    fn apply_staged_lending_repay(&mut self, tx: &LendingRepay) -> DefiResult<()> {
        let position = self.require_lending_position(&tx.position_id)?.clone();
        let spent = self.remove_staged_note(&tx.spent_debt_note_id, &tx.nullifier)?;
        if spent.asset_id != position.debt_asset_id
            || spent.owner_view_key != position.owner_view_key
        {
            return Err("staged lending repay debt note mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "lending_repay",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid lending repay authorization".to_string());
        }
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&position.debt_asset_id, tx.repay_fee);
        self.insert_staged_output_notes(&tx.output_notes)?;
        self.close_lending_position(&tx.position_id, "repaid")?;
        self.bump_lending_market_totals(
            &position.market_id,
            -(position.collateral_amount as i128),
            -(position.debt_amount as i128),
        )
    }

    fn apply_staged_lending_liquidation(&mut self, tx: &LendingLiquidation) -> DefiResult<()> {
        let position = self.require_lending_position(&tx.position_id)?.clone();
        let spent = self.remove_staged_note(&tx.spent_debt_note_id, &tx.nullifier)?;
        if spent.asset_id != position.debt_asset_id {
            return Err("staged lending liquidation debt note mismatch".to_string());
        }
        if !verify_authorization(
            &tx.signer_label,
            "lending_liquidation",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid lending liquidation authorization".to_string());
        }
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&position.debt_asset_id, tx.liquidation_fee);
        self.insert_staged_output_notes(&tx.output_notes)?;
        self.close_lending_position(&tx.position_id, "liquidated")?;
        self.bump_lending_market_totals(
            &position.market_id,
            -(position.collateral_amount as i128),
            -(position.debt_amount as i128),
        )
    }

    pub fn create_asset(
        &mut self,
        symbol: &str,
        issuer_policy: &str,
        supply_policy: &str,
        privacy_class: &str,
        max_supply: u64,
        metadata: &Value,
    ) -> DefiResult<Asset> {
        if !matches!(
            supply_policy,
            "mint-burn" | "fixed" | "bridge-mint-burn" | "amm-liquidity"
        ) {
            return Err("unsupported asset supply policy".to_string());
        }
        if supply_policy == "fixed" && max_supply == 0 {
            return Err("fixed supply assets require a positive max supply".to_string());
        }
        if supply_policy != "fixed" && max_supply != 0 && supply_policy != "mint-burn" {
            return Err("max_supply is only supported for native assets".to_string());
        }

        let normalized_symbol = symbol.to_ascii_uppercase();
        let metadata_hash = domain_hash("ASSET-METADATA", &[HashPart::Json(metadata)], 32);
        let asset_id = domain_hash(
            "ASSET-ID",
            &[
                HashPart::Str(&normalized_symbol),
                HashPart::Str(issuer_policy),
                HashPart::Str(supply_policy),
                HashPart::Str(privacy_class),
                HashPart::Str(&metadata_hash),
                HashPart::Int(max_supply as i128),
                HashPart::Int(self.assets.len() as i128),
            ],
            32,
        );
        let asset = Asset {
            asset_id: asset_id.clone(),
            symbol: normalized_symbol,
            issuer_policy: issuer_policy.to_string(),
            supply_policy: supply_policy.to_string(),
            privacy_class: privacy_class.to_string(),
            metadata_hash,
            max_supply,
        };
        self.assets.insert(asset_id.clone(), asset.clone());
        self.asset_supplies
            .insert(asset_id.clone(), AssetSupply::new(&asset_id));
        self.fees_collected.entry(asset_id).or_insert(0);
        Ok(asset)
    }

    pub fn create_native_asset(
        &mut self,
        symbol: &str,
        issuer_policy: &str,
        max_supply: u64,
    ) -> DefiResult<Asset> {
        let supply_policy = if max_supply == 0 {
            "mint-burn"
        } else {
            "fixed"
        };
        self.create_asset(
            symbol,
            issuer_policy,
            supply_policy,
            "shielded",
            max_supply,
            &json!({}),
        )
    }

    pub fn create_amm_pool(
        &mut self,
        asset_a_id: &str,
        asset_b_id: &str,
        fee_bps: u64,
        curve: &str,
    ) -> DefiResult<AmmPool> {
        self.require_asset(asset_a_id)?;
        self.require_asset(asset_b_id)?;
        if asset_a_id == asset_b_id {
            return Err("AMM pool requires two distinct assets".to_string());
        }
        if fee_bps >= 10_000 {
            return Err("fee_bps must be between 0 and 9999".to_string());
        }
        let curve = validate_amm_curve(curve)?;
        let pool_id = domain_hash(
            "AMM-POOL-ID",
            &[
                HashPart::Str(asset_a_id),
                HashPart::Str(asset_b_id),
                HashPart::Int(fee_bps as i128),
                HashPart::Str(&curve),
                HashPart::Int(self.pools.len() as i128),
            ],
            32,
        );
        let lp_asset = self.create_asset(
            &format!("LP{}", &pool_id[..8].to_ascii_uppercase()),
            &format!("amm:{pool_id}"),
            "amm-liquidity",
            "shielded",
            0,
            &json!({
                "kind": "amm_lp_token",
                "pool_id": pool_id,
                "asset_a_id": asset_a_id,
                "asset_b_id": asset_b_id,
                "curve": curve,
            }),
        )?;
        let pool = AmmPool {
            pool_id: pool_id.clone(),
            asset_a_id: asset_a_id.to_string(),
            asset_b_id: asset_b_id.to_string(),
            lp_asset_id: lp_asset.asset_id,
            reserve_a: 0,
            reserve_b: 0,
            total_lp: 0,
            fee_bps,
            curve,
        };
        self.pools.insert(pool_id, pool.clone());
        Ok(pool)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_sealed_swap_order_commitment(
        &mut self,
        pool_id: &str,
        note_in_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        recipient_view_key: &str,
        reveal_secret: &str,
        network_fee: u64,
        ttl_blocks: u64,
        min_reveal_height: Option<u64>,
        signer_label: Option<&str>,
    ) -> DefiResult<SealedSwapOrderCommitment> {
        if amount_in == 0 {
            return Err("sealed swap commitment amount_in must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("sealed swap commitment ttl must be positive".to_string());
        }
        if reveal_secret.is_empty() {
            return Err("sealed swap reveal secret is required".to_string());
        }
        let pool = self.require_pool(pool_id)?.clone();
        let note = self.require_note(note_in_id)?.clone();
        let signer_label = signer_label.unwrap_or(&note.owner_view_key).to_string();
        if signer_label != note.owner_view_key {
            return Err("sealed swap commitment signer does not own note".to_string());
        }
        if note.amount < amount_in + network_fee {
            return Err("sealed swap commitment note cannot cover amount plus fee".to_string());
        }
        let asset_out_id = sealed_swap_output_asset(&pool, &note.asset_id)?;
        let nullifier = note_nullifier(&note);
        self.check_nullifier_available(&nullifier)?;
        let min_reveal = min_reveal_height.unwrap_or(self.height + 1);
        if min_reveal < self.height {
            return Err("sealed swap commitment reveal height is in the past".to_string());
        }
        let expires_height = min_reveal
            .checked_add(ttl_blocks)
            .ok_or_else(|| "sealed swap commitment expiry overflow".to_string())?;
        let order_commitment = sealed_swap_order_commitment_hash(
            pool_id,
            &note.note_id,
            &nullifier,
            &note.asset_id,
            &asset_out_id,
            amount_in,
            min_amount_out,
            recipient_view_key,
            network_fee,
            reveal_secret,
        )?;
        let owner_commitment = sealed_swap_owner_commitment(&signer_label);
        let commitment_id = sealed_swap_order_commitment_id(
            pool_id,
            &note.asset_id,
            &asset_out_id,
            &owner_commitment,
            &order_commitment,
            min_reveal,
            expires_height,
        );
        if self
            .sealed_swap_order_commitments
            .contains_key(&commitment_id)
        {
            return Err("sealed swap commitment already exists".to_string());
        }
        let mut commitment = SealedSwapOrderCommitment {
            commitment_id,
            pool_id: pool_id.to_string(),
            asset_in_id: note.asset_id,
            asset_out_id,
            order_commitment,
            owner_commitment,
            min_reveal_height: min_reveal,
            expires_height,
            status: "active".to_string(),
            revealed_intent_hash: String::new(),
            revealed_at_height: 0,
            signer_label,
            authorization: empty_authorization(),
        };
        commitment.authorization = sign_authorization(
            &commitment.signer_label,
            "sealed_swap_order_commitment",
            &commitment.unsigned_record(),
        );
        self.verify_sealed_swap_order_commitment(&commitment)?;
        self.sealed_swap_order_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_sealed_swap_solver_bid(
        &mut self,
        pool_id: &str,
        commitment_ids: &[String],
        asset_in_id: &str,
        asset_out_id: &str,
        total_amount_in: u64,
        quoted_amount_out: u64,
        network_fee_total: u64,
        solver_label: &str,
        ttl_blocks: u64,
        expires_height: Option<u64>,
    ) -> DefiResult<SealedSwapSolverBid> {
        if solver_label.is_empty() {
            return Err("sealed swap solver label is required".to_string());
        }
        if commitment_ids.is_empty() {
            return Err("sealed swap solver bid requires commitments".to_string());
        }
        ensure_distinct(
            commitment_ids,
            "sealed swap solver bid commitment ids must be distinct",
        )?;
        if total_amount_in == 0 {
            return Err("sealed swap solver bid input must be positive".to_string());
        }
        if quoted_amount_out == 0 {
            return Err("sealed swap solver bid output must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("sealed swap solver bid ttl must be positive".to_string());
        }
        let pool = self.require_pool(pool_id)?.clone();
        if asset_in_id != pool.asset_a_id && asset_in_id != pool.asset_b_id {
            return Err("sealed swap solver bid asset does not match pool".to_string());
        }
        let expected_asset_out = sealed_swap_output_asset(&pool, asset_in_id)?;
        if asset_out_id != expected_asset_out {
            return Err("sealed swap solver bid output asset mismatch".to_string());
        }
        for commitment_id in commitment_ids {
            let commitment = self
                .sealed_swap_order_commitments
                .get(commitment_id)
                .ok_or_else(|| "unknown sealed swap commitment".to_string())?;
            self.verify_sealed_swap_order_commitment(commitment)?;
            if commitment.status != "active" {
                return Err("sealed swap commitment is not active".to_string());
            }
            if commitment.pool_id != pool_id {
                return Err("sealed swap solver bid commitment pool mismatch".to_string());
            }
            if commitment.asset_in_id != asset_in_id || commitment.asset_out_id != asset_out_id {
                return Err("sealed swap solver bid commitment asset mismatch".to_string());
            }
        }
        let expires = expires_height.unwrap_or(self.height + ttl_blocks);
        if expires < self.height {
            return Err("sealed swap solver bid expiry is in the past".to_string());
        }
        let batch_commitment_root = sealed_swap_batch_commitment_root(commitment_ids);
        let bid_id = sealed_swap_solver_bid_id(
            pool_id,
            solver_label,
            &batch_commitment_root,
            asset_in_id,
            asset_out_id,
            total_amount_in,
            quoted_amount_out,
            network_fee_total,
            expires,
        );
        if self.sealed_swap_solver_bids.contains_key(&bid_id) {
            return Err("sealed swap solver bid already exists".to_string());
        }
        let mut bid = SealedSwapSolverBid {
            bid_id,
            pool_id: pool_id.to_string(),
            solver_label: solver_label.to_string(),
            batch_commitment_root,
            asset_in_id: asset_in_id.to_string(),
            asset_out_id: asset_out_id.to_string(),
            total_amount_in,
            quoted_amount_out,
            network_fee_total,
            expires_height: expires,
            status: "active".to_string(),
            settled_tx_public_hash: String::new(),
            settled_at_height: 0,
            authorization: empty_authorization(),
        };
        bid.authorization = sign_authorization(
            &bid.solver_label,
            "sealed_swap_solver_bid",
            &bid.unsigned_record(),
        );
        self.verify_sealed_swap_solver_bid(&bid)?;
        self.sealed_swap_solver_bids
            .insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn submit_amm_sealed_batch_swap(
        &mut self,
        pool_id: &str,
        reveals: &[SealedSwapIntentReveal],
        solver_bid_id: Option<&str>,
        solver_label: Option<&str>,
    ) -> DefiResult<AmmSealedBatchSwap> {
        if reveals.is_empty() {
            return Err("sealed batch swap requires input reveals".to_string());
        }
        let solver_label = solver_label.unwrap_or("sealed-swap-solver").to_string();
        if solver_label.is_empty() {
            return Err("sealed swap solver label is required".to_string());
        }
        let spent_note_ids = reveals
            .iter()
            .map(|reveal| reveal.spent_note_id.clone())
            .collect::<Vec<_>>();
        ensure_distinct(&spent_note_ids, "sealed batch swap notes must be distinct")?;
        let commitment_ids = reveals
            .iter()
            .map(|reveal| reveal.commitment_id.clone())
            .collect::<Vec<_>>();
        ensure_distinct(
            &commitment_ids,
            "sealed batch swap commitments must be distinct",
        )?;
        let commitment_reveal_secrets = reveals
            .iter()
            .map(|reveal| reveal.reveal_secret.clone())
            .collect::<Vec<_>>();
        if commitment_reveal_secrets.iter().any(String::is_empty) {
            return Err("sealed swap reveal secret is required".to_string());
        }

        let pool = self.require_pool(pool_id)?.clone();
        let input_notes = spent_note_ids
            .iter()
            .map(|note_id| self.require_note(note_id).cloned())
            .collect::<DefiResult<Vec<_>>>()?;
        let asset_in_id = input_notes
            .first()
            .map(|note| note.asset_id.clone())
            .ok_or_else(|| "sealed batch swap requires input notes".to_string())?;
        if input_notes.iter().any(|note| note.asset_id != asset_in_id) {
            return Err("sealed swap input notes must share one asset".to_string());
        }
        let (reserve_in, reserve_out, asset_out_id) = amm_asset_view(&pool, &asset_in_id)?;
        if reserve_in == 0 || reserve_out == 0 {
            return Err("pool has no liquidity".to_string());
        }

        let mut intents = Vec::with_capacity(reveals.len());
        let mut total_amount_in = 0_u64;
        let mut network_fee_total = 0_u64;
        let mut nullifiers = Vec::with_capacity(reveals.len());
        for (reveal, note) in reveals.iter().zip(input_notes.iter()) {
            if reveal.amount_in == 0 {
                return Err("sealed swap amounts must be positive".to_string());
            }
            let required = reveal
                .amount_in
                .checked_add(reveal.network_fee)
                .ok_or_else(|| "sealed swap required amount overflow".to_string())?;
            if note.amount < required {
                return Err("sealed swap note cannot cover amount plus network fee".to_string());
            }
            let signer_label = reveal
                .signer_label
                .as_deref()
                .unwrap_or(&note.owner_view_key)
                .to_string();
            if signer_label != note.owner_view_key {
                return Err("sealed swap signer does not own note".to_string());
            }
            let nullifier = note_nullifier(note);
            nullifiers.push(nullifier.clone());
            self.check_nullifier_available(&nullifier)?;

            let commitment = self
                .sealed_swap_order_commitments
                .get(&reveal.commitment_id)
                .ok_or_else(|| "unknown sealed swap commitment".to_string())?;
            self.verify_sealed_swap_order_commitment(commitment)?;
            if commitment.status != "active" {
                return Err("sealed swap commitment is not active".to_string());
            }
            if self.height < commitment.min_reveal_height {
                return Err("sealed swap commitment cannot reveal yet".to_string());
            }
            if self.height > commitment.expires_height {
                return Err("sealed swap commitment has expired".to_string());
            }
            if commitment.pool_id != pool_id {
                return Err("sealed swap commitment pool mismatch".to_string());
            }
            if commitment.asset_in_id != asset_in_id || commitment.asset_out_id != asset_out_id {
                return Err("sealed swap commitment asset mismatch".to_string());
            }
            if commitment.owner_commitment != sealed_swap_owner_commitment(&signer_label) {
                return Err("sealed swap commitment signer mismatch".to_string());
            }
            let expected_order_commitment = sealed_swap_order_commitment_hash(
                pool_id,
                &note.note_id,
                &nullifier,
                &asset_in_id,
                &asset_out_id,
                reveal.amount_in,
                reveal.min_amount_out,
                &reveal.recipient_view_key,
                reveal.network_fee,
                &reveal.reveal_secret,
            )?;
            if commitment.order_commitment != expected_order_commitment {
                return Err("sealed swap commitment opening mismatch".to_string());
            }

            let mut intent = SealedSwapIntent {
                pool_id: pool_id.to_string(),
                spent_note_id: note.note_id.clone(),
                nullifier,
                asset_in_id: asset_in_id.clone(),
                asset_out_id: asset_out_id.clone(),
                amount_in: reveal.amount_in,
                min_amount_out: reveal.min_amount_out,
                recipient_view_key: reveal.recipient_view_key.clone(),
                network_fee: reveal.network_fee,
                signer_label,
                authorization: empty_authorization(),
            };
            intent.authorization = sign_authorization(
                &intent.signer_label,
                "sealed_amm_swap_intent",
                &intent.unsigned_record(),
            );
            self.verify_sealed_swap_intent(&intent)?;
            total_amount_in = total_amount_in
                .checked_add(reveal.amount_in)
                .ok_or_else(|| "sealed batch swap total input overflow".to_string())?;
            network_fee_total = network_fee_total
                .checked_add(reveal.network_fee)
                .ok_or_else(|| "sealed batch swap network fee overflow".to_string())?;
            intents.push(intent);
        }
        ensure_distinct(&nullifiers, "duplicate nullifier in transaction")?;

        let total_amount_out = amm_output_amount(&pool, reserve_in, reserve_out, total_amount_in)?;
        if total_amount_out == 0 {
            return Err("sealed batch swap outputs zero".to_string());
        }
        let mut amount_outs = Vec::with_capacity(intents.len());
        let mut remaining_out = total_amount_out;
        for (index, intent) in intents.iter().enumerate() {
            let amount_out = if index == intents.len() - 1 {
                remaining_out
            } else {
                let proportional = ((total_amount_out as u128) * (intent.amount_in as u128)
                    / (total_amount_in as u128)) as u64;
                remaining_out = remaining_out
                    .checked_sub(proportional)
                    .ok_or_else(|| "sealed batch swap output allocation underflow".to_string())?;
                proportional
            };
            if amount_out < intent.min_amount_out {
                return Err("sealed swap output below minimum".to_string());
            }
            amount_outs.push(amount_out);
        }

        let mut fills = Vec::with_capacity(intents.len());
        for ((intent, note), amount_out) in intents
            .into_iter()
            .zip(input_notes.iter())
            .zip(amount_outs.into_iter())
        {
            let output_note = Note::create(
                &intent.recipient_view_key,
                &intent.asset_out_id,
                amount_out,
                self.next_nonce(),
            );
            let change_amount = note.amount - intent.amount_in - intent.network_fee;
            let change_note = if change_amount == 0 {
                None
            } else {
                Some(Note::create(
                    &note.owner_view_key,
                    &intent.asset_in_id,
                    change_amount,
                    self.next_nonce(),
                ))
            };
            fills.push(SealedSwapFill {
                intent,
                amount_out,
                output_note,
                change_note,
            });
        }

        let sealed_output_notes = fills
            .iter()
            .flat_map(SealedSwapFill::output_notes)
            .collect::<Vec<_>>();
        let intent_hashes = fills
            .iter()
            .map(|fill| fill.intent.intent_hash())
            .collect::<Vec<_>>();
        let encrypted_payload_hash = domain_hash(
            "SEALED-AMM-BATCH-SWAP-PAYLOAD",
            &[
                HashPart::Str(pool_id),
                HashPart::Json(&json!(intent_hashes)),
                HashPart::Str(&asset_in_id),
                HashPart::Str(&asset_out_id),
                HashPart::Int(total_amount_in as i128),
                HashPart::Int(total_amount_out as i128),
                HashPart::Int(network_fee_total as i128),
                HashPart::Json(&output_commitments(&sealed_output_notes)),
            ],
            32,
        );
        let updated_pool =
            updated_pool_for_swap(&pool, &asset_in_id, total_amount_in, total_amount_out)?;
        let proof_system = "devnet-mock-sealed-amm-batch-swap-proof".to_string();
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "kind": "sealed_amm_batch_swap",
                "pool_before": pool.public_record(),
                "pool_after": updated_pool.public_record(),
                "intent_root": merkle_root(
                    "SEALED-AMM-SWAP-INTENT",
                    &fills.iter().map(|fill| fill.intent.public_record()).collect::<Vec<_>>(),
                ),
                "commitment_root": sealed_swap_batch_commitment_root(&commitment_ids),
                "nullifiers": &nullifiers,
                "asset_in_id": &asset_in_id,
                "asset_out_id": &asset_out_id,
                "total_amount_in": total_amount_in,
                "total_amount_out": total_amount_out,
                "network_fee_total": network_fee_total,
                "solver_commitment": sealed_swap_solver_commitment(&solver_label),
                "output_commitments": output_commitments(&sealed_output_notes),
                "encrypted_payload_hash": &encrypted_payload_hash,
            }),
            &json!({
                "input_notes": input_notes.iter().map(Note::state_record).collect::<Vec<_>>(),
                "fills": fills.iter().map(SealedSwapFill::state_record).collect::<Vec<_>>(),
                "commitment_reveal_secrets": &commitment_reveal_secrets,
            }),
        );
        let tx = AmmSealedBatchSwap {
            pool_id: pool_id.to_string(),
            fills,
            asset_in_id: asset_in_id.clone(),
            asset_out_id,
            total_amount_in,
            total_amount_out,
            network_fee_total,
            encrypted_payload_hash,
            commitment_ids,
            commitment_reveal_secrets,
            solver_bid_id: solver_bid_id.unwrap_or_default().to_string(),
            solver_label,
            proof_system,
            privacy_proof,
        };
        self.verify_amm_sealed_batch_swap(&tx)?;
        let receipt = self.build_sealed_swap_settlement_receipt(&tx, &pool, &updated_pool)?;

        for note_id in &spent_note_ids {
            self.notes.remove(note_id);
        }
        for nullifier in tx.fills.iter().map(|fill| fill.intent.nullifier.clone()) {
            self.spent_nullifiers.push(nullifier);
        }
        self.add_fee(&tx.asset_in_id, tx.network_fee_total);
        self.pools.insert(pool_id.to_string(), updated_pool.clone());
        for output in tx.output_notes() {
            self.notes.insert(output.note_id.clone(), output);
        }
        self.mark_sealed_swap_commitments_revealed(&tx)?;
        self.mark_sealed_swap_solver_bids_settled(&tx)?;
        self.verify_sealed_swap_settlement_receipt(&receipt, &tx, &pool, &updated_pool)?;
        self.sealed_swap_settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(tx)
    }

    pub fn expire_sealed_swap_auctions(&mut self) -> DefiResult<(Vec<String>, Vec<String>)> {
        let mut expired_commitments = Vec::new();
        let mut expired_bids = Vec::new();
        let height = self.height;
        let commitment_ids = self
            .sealed_swap_order_commitments
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for commitment_id in commitment_ids {
            let should_expire = self
                .sealed_swap_order_commitments
                .get(&commitment_id)
                .map(|commitment| {
                    commitment.status == "active" && height > commitment.expires_height
                })
                .unwrap_or(false);
            if should_expire {
                let mut commitment = self
                    .sealed_swap_order_commitments
                    .get(&commitment_id)
                    .cloned()
                    .ok_or_else(|| "unknown sealed swap commitment".to_string())?;
                commitment.status = "expired".to_string();
                self.verify_sealed_swap_order_commitment(&commitment)?;
                self.sealed_swap_order_commitments
                    .insert(commitment_id.clone(), commitment);
                expired_commitments.push(commitment_id);
            }
        }
        let bid_ids = self
            .sealed_swap_solver_bids
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for bid_id in bid_ids {
            let should_expire = self
                .sealed_swap_solver_bids
                .get(&bid_id)
                .map(|bid| bid.status == "active" && height > bid.expires_height)
                .unwrap_or(false);
            if should_expire {
                let mut bid = self
                    .sealed_swap_solver_bids
                    .get(&bid_id)
                    .cloned()
                    .ok_or_else(|| "unknown sealed swap solver bid".to_string())?;
                bid.status = "expired".to_string();
                self.verify_sealed_swap_solver_bid(&bid)?;
                self.sealed_swap_solver_bids.insert(bid_id.clone(), bid);
                expired_bids.push(bid_id);
            }
        }
        Ok((expired_commitments, expired_bids))
    }

    pub fn oracle_feed_id(&self, base_asset_id: &str, quote_asset_id: &str) -> String {
        oracle_feed_id(base_asset_id, quote_asset_id)
    }

    pub fn publish_oracle_price(
        &mut self,
        base_asset_id: &str,
        quote_asset_id: &str,
        price_numerator: u64,
        price_denominator: u64,
        confidence_bps: u64,
        publisher_labels: &[&str],
    ) -> DefiResult<OraclePriceFeed> {
        self.require_asset(base_asset_id)?;
        self.require_asset(quote_asset_id)?;
        if base_asset_id == quote_asset_id {
            return Err("oracle price requires two distinct assets".to_string());
        }
        if price_numerator == 0 || price_denominator == 0 {
            return Err("oracle price must be positive".to_string());
        }
        if confidence_bps > 10_000 {
            return Err("confidence_bps must be between 0 and 10000".to_string());
        }
        if publisher_labels.is_empty() {
            return Err("at least one oracle publisher is required".to_string());
        }
        let feed_id = self.oracle_feed_id(base_asset_id, quote_asset_id);
        let round_id = self
            .oracle_prices
            .get(&feed_id)
            .map(|feed| feed.round_id + 1)
            .unwrap_or(1);
        let mut feed = OraclePriceFeed {
            feed_id: feed_id.clone(),
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            price_numerator,
            price_denominator,
            confidence_bps,
            round_id,
            published_at_height: self.height,
            attestations: Vec::new(),
        };
        feed.attestations = publisher_labels
            .iter()
            .map(|label| OraclePriceAttestation {
                publisher_label: (*label).to_string(),
                authorization: sign_authorization(
                    label,
                    "oracle_price_attestation",
                    &feed.unsigned_record(),
                ),
            })
            .collect();
        self.verify_oracle_price_feed(&feed)?;
        self.oracle_prices.insert(feed_id, feed.clone());
        Ok(feed)
    }

    pub fn create_lending_market(
        &mut self,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        collateral_factor_bps: u64,
        liquidation_threshold_bps: u64,
        oracle_feed_id: Option<&str>,
    ) -> DefiResult<LendingMarket> {
        self.require_asset(collateral_asset_id)?;
        self.require_asset(debt_asset_id)?;
        if collateral_asset_id == debt_asset_id {
            return Err("lending market requires two distinct assets".to_string());
        }
        if collateral_factor_bps == 0 || collateral_factor_bps >= 10_000 {
            return Err("collateral_factor_bps must be between 1 and 9999".to_string());
        }
        if liquidation_threshold_bps <= collateral_factor_bps || liquidation_threshold_bps > 10_000
        {
            return Err("liquidation_threshold_bps must exceed collateral factor".to_string());
        }
        let oracle_feed_id = oracle_feed_id.unwrap_or_default().to_string();
        if !oracle_feed_id.is_empty() {
            let feed = self
                .oracle_prices
                .get(&oracle_feed_id)
                .ok_or_else(|| "unknown oracle feed".to_string())?;
            if feed.base_asset_id != collateral_asset_id || feed.quote_asset_id != debt_asset_id {
                return Err("oracle feed does not match lending market assets".to_string());
            }
        }
        let market_id = domain_hash(
            "LENDING-MARKET-ID",
            &[
                HashPart::Str(collateral_asset_id),
                HashPart::Str(debt_asset_id),
                HashPart::Int(collateral_factor_bps as i128),
                HashPart::Int(liquidation_threshold_bps as i128),
                HashPart::Str(&oracle_feed_id),
                HashPart::Int(self.lending_markets.len() as i128),
            ],
            32,
        );
        let market = LendingMarket {
            market_id: market_id.clone(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            collateral_factor_bps,
            liquidation_threshold_bps,
            oracle_feed_id,
            total_collateral: 0,
            total_debt: 0,
            status: "active".to_string(),
        };
        self.lending_markets.insert(market_id, market.clone());
        Ok(market)
    }

    pub fn mint(&mut self, asset_id: &str, owner_view_key: &str, amount: u64) -> DefiResult<Note> {
        self.require_asset(asset_id)?;
        if amount == 0 {
            return Err("mint amount must be positive".to_string());
        }
        let note = Note::create(owner_view_key, asset_id, amount, self.next_nonce());
        self.notes.insert(note.note_id.clone(), note.clone());
        self.update_asset_supply(asset_id, amount, 0)?;
        Ok(note)
    }

    pub fn submit_asset_mint(
        &mut self,
        asset_id: &str,
        recipient_view_key: &str,
        amount: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<AssetMint> {
        let asset = self.require_asset(asset_id)?.clone();
        if !asset_supports_native_mint_burn(&asset) {
            return Err("asset does not support native mint-burn".to_string());
        }
        if amount == 0 {
            return Err("asset mint amount must be positive".to_string());
        }
        self.enforce_asset_mint_cap(&asset, amount)?;
        let signer_label = signer_label
            .map(ToString::to_string)
            .unwrap_or_else(|| asset_issuer_label(&asset));
        if signer_label != asset_issuer_label(&asset) {
            return Err("asset mint signer does not match issuer policy".to_string());
        }
        let output_note = Note::create(recipient_view_key, asset_id, amount, self.next_nonce());
        let mut mint = AssetMint {
            asset_id: asset_id.to_string(),
            amount,
            output_note,
            signer_label,
            authorization: empty_authorization(),
            proof_system: "devnet-pq-issuer-asset-mint".to_string(),
        };
        mint.authorization =
            sign_authorization(&mint.signer_label, "asset_mint", &mint.unsigned_record());
        if !verify_authorization(
            &mint.signer_label,
            "asset_mint",
            &mint.unsigned_record(),
            &mint.authorization,
        ) {
            return Err("invalid asset mint authorization".to_string());
        }
        self.notes
            .insert(mint.output_note.note_id.clone(), mint.output_note.clone());
        self.update_asset_supply(asset_id, amount, 0)?;
        Ok(mint)
    }

    pub fn submit_asset_burn(
        &mut self,
        spent_note_id: &str,
        amount: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<AssetBurn> {
        if amount == 0 {
            return Err("asset burn amount must be positive".to_string());
        }
        let spent = self.require_note(spent_note_id)?.clone();
        let asset = self.require_asset(&spent.asset_id)?.clone();
        if !asset_supports_native_mint_burn(&asset) {
            return Err("asset does not support native mint-burn".to_string());
        }
        let signer_label = signer_label.unwrap_or(&spent.owner_view_key).to_string();
        if signer_label != spent.owner_view_key {
            return Err("signer does not own the asset burn note".to_string());
        }
        if amount > spent.amount {
            return Err("asset burn amount exceeds note value".to_string());
        }
        let nullifier = note_nullifier(&spent);
        self.check_nullifier_available(&nullifier)?;
        let mut outputs = Vec::new();
        let change = spent.amount - amount;
        if change != 0 {
            outputs.push(Note::create(
                &spent.owner_view_key,
                &spent.asset_id,
                change,
                self.next_nonce(),
            ));
        }
        let proof_system = "devnet-mock-private-asset-burn-proof".to_string();
        let output_commitments = outputs
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect::<Vec<_>>();
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "asset_id": spent.asset_id,
                "amount": amount,
                "nullifier": nullifier,
                "output_commitments": output_commitments,
            }),
            &json!({
                "spent_note": spent.state_record(),
                "output_notes": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
            }),
        );
        let mut burn = AssetBurn {
            spent_note_id: spent_note_id.to_string(),
            nullifier,
            asset_id: spent.asset_id.clone(),
            amount,
            output_notes: outputs,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        burn.authorization = sign_authorization(
            &burn.signer_label,
            "asset_burn",
            &burn.unsigned_record(true),
        );
        self.notes.remove(spent_note_id);
        self.spent_nullifiers.push(burn.nullifier.clone());
        for output in &burn.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        self.update_asset_supply(&burn.asset_id, 0, amount)?;
        Ok(burn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_liquidity_add(
        &mut self,
        pool_id: &str,
        note_a_id: &str,
        note_b_id: &str,
        amount_a: u64,
        amount_b: u64,
        owner_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<AmmLiquidityAdd> {
        if amount_a == 0 || amount_b == 0 {
            return Err("liquidity amounts must be positive".to_string());
        }
        let pool = self.require_pool(pool_id)?.clone();
        let note_a = self.require_note(note_a_id)?.clone();
        let note_b = self.require_note(note_b_id)?.clone();
        let signer_label = signer_label.unwrap_or(&note_a.owner_view_key).to_string();
        if signer_label != note_a.owner_view_key || signer_label != note_b.owner_view_key {
            return Err("signer must own both liquidity notes".to_string());
        }
        if note_a.asset_id != pool.asset_a_id || note_b.asset_id != pool.asset_b_id {
            return Err("liquidity notes do not match pool assets".to_string());
        }
        if note_a.amount < amount_a + network_fee {
            return Err("asset A note cannot cover amount plus network fee".to_string());
        }
        if note_b.amount < amount_b {
            return Err("asset B note cannot cover amount".to_string());
        }
        let nullifier_a = note_nullifier(&note_a);
        let nullifier_b = note_nullifier(&note_b);
        self.check_nullifier_available(&nullifier_a)?;
        self.check_nullifier_available(&nullifier_b)?;
        let lp_minted = amm_lp_minted(&pool, amount_a, amount_b)?;
        if lp_minted == 0 {
            return Err("liquidity deposit mints zero LP notes".to_string());
        }
        let mut outputs = vec![Note::create(
            owner_view_key,
            &pool.lp_asset_id,
            lp_minted,
            self.next_nonce(),
        )];
        let change_a = note_a.amount - amount_a - network_fee;
        let change_b = note_b.amount - amount_b;
        if change_a != 0 {
            outputs.push(Note::create(
                &note_a.owner_view_key,
                &note_a.asset_id,
                change_a,
                self.next_nonce(),
            ));
        }
        if change_b != 0 {
            outputs.push(Note::create(
                &note_b.owner_view_key,
                &note_b.asset_id,
                change_b,
                self.next_nonce(),
            ));
        }
        let output_commitments = outputs
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect::<Vec<_>>();
        let encrypted_payload_hash = domain_hash(
            "AMM-LIQUIDITY-PAYLOAD",
            &[
                HashPart::Str(pool_id),
                HashPart::Str(note_a_id),
                HashPart::Str(note_b_id),
                HashPart::Int(amount_a as i128),
                HashPart::Int(amount_b as i128),
                HashPart::Int(lp_minted as i128),
                HashPart::Int(network_fee as i128),
                HashPart::Json(&Value::Array(output_commitments.clone())),
            ],
            32,
        );
        let proof_system = "devnet-mock-amm-liquidity-proof".to_string();
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "pool_id": pool_id,
                "nullifiers": [nullifier_a, nullifier_b],
                "amount_a": amount_a,
                "amount_b": amount_b,
                "lp_minted": lp_minted,
                "output_commitments": output_commitments,
            }),
            &json!({
                "spent_notes": [note_a.state_record(), note_b.state_record()],
                "outputs": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
                "pool_before": pool.public_record(),
            }),
        );
        let mut tx = AmmLiquidityAdd {
            pool_id: pool_id.to_string(),
            spent_note_a_id: note_a_id.to_string(),
            spent_note_b_id: note_b_id.to_string(),
            nullifier_a,
            nullifier_b,
            amount_a,
            amount_b,
            lp_minted,
            output_notes: outputs,
            network_fee,
            encrypted_payload_hash,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        tx.authorization = sign_authorization(
            &tx.signer_label,
            "amm_liquidity_add",
            &tx.unsigned_record(true),
        );
        self.notes.remove(note_a_id);
        self.notes.remove(note_b_id);
        self.spent_nullifiers.push(tx.nullifier_a.clone());
        self.spent_nullifiers.push(tx.nullifier_b.clone());
        self.add_fee(&note_a.asset_id, network_fee);
        self.pools.insert(
            pool_id.to_string(),
            AmmPool {
                reserve_a: pool.reserve_a + amount_a,
                reserve_b: pool.reserve_b + amount_b,
                total_lp: pool.total_lp + lp_minted,
                ..pool
            },
        );
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        self.update_asset_supply(&tx.output_notes[0].asset_id, lp_minted, 0)?;
        Ok(tx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_swap(
        &mut self,
        pool_id: &str,
        note_in_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        recipient_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<AmmSwap> {
        if amount_in == 0 {
            return Err("swap amount_in must be positive".to_string());
        }
        let pool = self.require_pool(pool_id)?.clone();
        let note_in = self.require_note(note_in_id)?.clone();
        let signer_label = signer_label.unwrap_or(&note_in.owner_view_key).to_string();
        if signer_label != note_in.owner_view_key {
            return Err("signer does not own the swap note".to_string());
        }
        let (reserve_in, reserve_out, asset_out_id) = amm_asset_view(&pool, &note_in.asset_id)?;
        if reserve_in == 0 || reserve_out == 0 {
            return Err("pool has no liquidity".to_string());
        }
        if note_in.amount < amount_in + network_fee {
            return Err("swap note cannot cover amount plus network fee".to_string());
        }
        let amount_out = amm_output_amount(&pool, reserve_in, reserve_out, amount_in)?;
        if amount_out == 0 {
            return Err("swap outputs zero".to_string());
        }
        if amount_out < min_amount_out {
            return Err("swap output below minimum".to_string());
        }
        let nullifier = note_nullifier(&note_in);
        self.check_nullifier_available(&nullifier)?;
        let mut outputs = vec![Note::create(
            recipient_view_key,
            &asset_out_id,
            amount_out,
            self.next_nonce(),
        )];
        let change = note_in.amount - amount_in - network_fee;
        if change != 0 {
            outputs.push(Note::create(
                &note_in.owner_view_key,
                &note_in.asset_id,
                change,
                self.next_nonce(),
            ));
        }
        let output_commitments = outputs
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect::<Vec<_>>();
        let encrypted_payload_hash = domain_hash(
            "AMM-SWAP-PAYLOAD",
            &[
                HashPart::Str(pool_id),
                HashPart::Str(note_in_id),
                HashPart::Str(&note_in.asset_id),
                HashPart::Str(&asset_out_id),
                HashPart::Int(amount_in as i128),
                HashPart::Int(amount_out as i128),
                HashPart::Int(network_fee as i128),
                HashPart::Json(&Value::Array(output_commitments.clone())),
            ],
            32,
        );
        let proof_system = "devnet-mock-amm-swap-proof".to_string();
        let updated_pool = updated_pool_for_swap(&pool, &note_in.asset_id, amount_in, amount_out)?;
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "pool_id": pool_id,
                "nullifier": nullifier,
                "asset_in_id": note_in.asset_id,
                "asset_out_id": asset_out_id,
                "amount_in": amount_in,
                "amount_out": amount_out,
                "output_commitments": output_commitments,
            }),
            &json!({
                "spent_note": note_in.state_record(),
                "outputs": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
                "pool_before": pool.public_record(),
                "pool_after": updated_pool.public_record(),
            }),
        );
        let mut tx = AmmSwap {
            pool_id: pool_id.to_string(),
            spent_note_id: note_in_id.to_string(),
            nullifier,
            asset_in_id: note_in.asset_id.clone(),
            asset_out_id,
            amount_in,
            amount_out,
            output_notes: outputs,
            network_fee,
            encrypted_payload_hash,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        tx.authorization =
            sign_authorization(&tx.signer_label, "amm_swap", &tx.unsigned_record(true));
        self.notes.remove(note_in_id);
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&tx.asset_in_id, network_fee);
        self.pools.insert(pool_id.to_string(), updated_pool);
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        Ok(tx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_batch_swap(
        &mut self,
        pool_id: &str,
        note_in_ids: &[&str],
        amount_ins: &[u64],
        min_total_amount_out: u64,
        recipient_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<AmmBatchSwap> {
        if note_in_ids.is_empty() {
            return Err("batch swap requires input notes".to_string());
        }
        if note_in_ids.len() != amount_ins.len() {
            return Err("batch swap note and amount counts differ".to_string());
        }
        let mut unique_note_ids = note_in_ids.to_vec();
        unique_note_ids.sort_unstable();
        unique_note_ids.dedup();
        if unique_note_ids.len() != note_in_ids.len() {
            return Err("batch swap notes must be distinct".to_string());
        }
        if amount_ins.iter().any(|amount| *amount == 0) {
            return Err("batch swap amounts must be positive".to_string());
        }
        let pool = self.require_pool(pool_id)?.clone();
        let input_notes = note_in_ids
            .iter()
            .map(|note_id| self.require_note(note_id).cloned())
            .collect::<DefiResult<Vec<_>>>()?;
        let signer_label = signer_label
            .unwrap_or(&input_notes[0].owner_view_key)
            .to_string();
        if input_notes
            .iter()
            .any(|note| note.owner_view_key != signer_label)
        {
            return Err("signer must own all batch swap notes".to_string());
        }
        let asset_in_id = input_notes[0].asset_id.clone();
        if input_notes.iter().any(|note| note.asset_id != asset_in_id) {
            return Err("batch swap input notes must share one asset".to_string());
        }
        let (reserve_in, reserve_out, asset_out_id) = amm_asset_view(&pool, &asset_in_id)?;
        if reserve_in == 0 || reserve_out == 0 {
            return Err("pool has no liquidity".to_string());
        }
        let total_amount_in = amount_ins
            .iter()
            .try_fold(0_u64, |acc, amount| acc.checked_add(*amount))
            .ok_or_else(|| "batch swap total input overflow".to_string())?;
        let total_available = input_notes
            .iter()
            .try_fold(0_u64, |acc, note| acc.checked_add(note.amount))
            .ok_or_else(|| "batch swap available amount overflow".to_string())?;
        if input_notes
            .iter()
            .zip(amount_ins.iter())
            .any(|(note, amount)| note.amount < *amount)
        {
            return Err("batch swap note cannot cover amount".to_string());
        }
        let required = total_amount_in
            .checked_add(network_fee)
            .ok_or_else(|| "batch swap required amount overflow".to_string())?;
        if total_available < required {
            return Err("batch swap notes cannot cover amount plus network fee".to_string());
        }
        let total_amount_out = amm_output_amount(&pool, reserve_in, reserve_out, total_amount_in)?;
        if total_amount_out == 0 {
            return Err("batch swap outputs zero".to_string());
        }
        if total_amount_out < min_total_amount_out {
            return Err("batch swap output below minimum".to_string());
        }
        let nullifiers = input_notes.iter().map(note_nullifier).collect::<Vec<_>>();
        ensure_distinct(&nullifiers, "duplicate nullifier in transaction")?;
        for nullifier in &nullifiers {
            self.check_nullifier_available(nullifier)?;
        }
        let mut outputs = vec![Note::create(
            recipient_view_key,
            &asset_out_id,
            total_amount_out,
            self.next_nonce(),
        )];
        let mut remaining_fee = network_fee;
        for (note, amount_in) in input_notes.iter().zip(amount_ins.iter()) {
            let available_for_fee = note.amount - amount_in;
            let fee_from_note = std::cmp::min(remaining_fee, available_for_fee);
            remaining_fee -= fee_from_note;
            let change = note.amount - amount_in - fee_from_note;
            if change != 0 {
                outputs.push(Note::create(
                    &note.owner_view_key,
                    &note.asset_id,
                    change,
                    self.next_nonce(),
                ));
            }
        }
        if remaining_fee != 0 {
            return Err("batch swap notes cannot cover network fee".to_string());
        }
        let encrypted_payload_hash = domain_hash(
            "AMM-BATCH-SWAP-PAYLOAD",
            &[
                HashPart::Str(pool_id),
                HashPart::Json(&json!(note_in_ids)),
                HashPart::Str(&asset_in_id),
                HashPart::Str(&asset_out_id),
                HashPart::Json(&json!(amount_ins)),
                HashPart::Int(total_amount_in as i128),
                HashPart::Int(total_amount_out as i128),
                HashPart::Int(network_fee as i128),
                HashPart::Json(&output_commitments(&outputs)),
            ],
            32,
        );
        let updated_pool =
            updated_pool_for_swap(&pool, &asset_in_id, total_amount_in, total_amount_out)?;
        let proof_system = "devnet-mock-amm-batch-swap-proof".to_string();
        let output_totals = note_totals_by_asset(&outputs)?;
        let expected_change = total_available - total_amount_in - network_fee;
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "kind": "amm_batch_swap",
                "pool_before": pool.public_record(),
                "input_commitments": input_notes.iter().map(|note| note.commitment.clone()).collect::<Vec<_>>(),
                "nullifiers": nullifiers,
                "asset_in_id": asset_in_id,
                "asset_out_id": asset_out_id,
                "amount_ins": amount_ins,
                "total_amount_in": total_amount_in,
                "total_amount_out": total_amount_out,
                "output_commitments": output_commitments(&outputs),
                "network_fee": network_fee,
                "encrypted_payload_hash": encrypted_payload_hash,
            }),
            &json!({
                "input_notes": input_notes.iter().map(Note::state_record).collect::<Vec<_>>(),
                "output_notes": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
                "output_totals": output_totals,
                "expected_change": expected_change,
            }),
        );
        let mut tx = AmmBatchSwap {
            pool_id: pool_id.to_string(),
            spent_note_ids: note_in_ids
                .iter()
                .map(|note_id| (*note_id).to_string())
                .collect(),
            nullifiers,
            asset_in_id,
            asset_out_id,
            amount_ins: amount_ins.to_vec(),
            total_amount_in,
            total_amount_out,
            output_notes: outputs,
            network_fee,
            encrypted_payload_hash,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        tx.authorization = sign_authorization(
            &tx.signer_label,
            "amm_batch_swap",
            &tx.unsigned_record(true),
        );
        if !verify_authorization(
            &tx.signer_label,
            "amm_batch_swap",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid AMM batch swap authorization".to_string());
        }
        for note_id in &tx.spent_note_ids {
            self.notes.remove(note_id);
        }
        for nullifier in &tx.nullifiers {
            self.spent_nullifiers.push(nullifier.clone());
        }
        self.add_fee(&tx.asset_in_id, network_fee);
        self.pools.insert(pool_id.to_string(), updated_pool);
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        Ok(tx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_route_swap(
        &mut self,
        pool_ids: &[&str],
        note_in_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        recipient_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<AmmRouteSwap> {
        if pool_ids.is_empty() {
            return Err("route swap requires at least one pool".to_string());
        }
        if amount_in == 0 {
            return Err("route swap amount_in must be positive".to_string());
        }
        let note_in = self.require_note(note_in_id)?.clone();
        let signer_label = signer_label.unwrap_or(&note_in.owner_view_key).to_string();
        if signer_label != note_in.owner_view_key {
            return Err("signer does not own the route swap note".to_string());
        }
        let required = amount_in
            .checked_add(network_fee)
            .ok_or_else(|| "route swap required amount overflow".to_string())?;
        if note_in.amount < required {
            return Err("route swap note cannot cover amount plus network fee".to_string());
        }
        let route_pool_ids = pool_ids
            .iter()
            .map(|pool_id| (*pool_id).to_string())
            .collect::<Vec<_>>();
        let simulation = self.simulate_amm_route(&route_pool_ids, &note_in.asset_id, amount_in)?;
        if simulation.amount_out < min_amount_out {
            return Err("route swap output below minimum".to_string());
        }
        let nullifier = note_nullifier(&note_in);
        self.check_nullifier_available(&nullifier)?;
        let mut outputs = vec![Note::create(
            recipient_view_key,
            simulation
                .asset_path
                .last()
                .ok_or_else(|| "route swap asset path mismatch".to_string())?,
            simulation.amount_out,
            self.next_nonce(),
        )];
        let change = note_in.amount - amount_in - network_fee;
        if change != 0 {
            outputs.push(Note::create(
                &note_in.owner_view_key,
                &note_in.asset_id,
                change,
                self.next_nonce(),
            ));
        }
        let encrypted_payload_hash = domain_hash(
            "AMM-ROUTE-SWAP-PAYLOAD",
            &[
                HashPart::Json(&json!(route_pool_ids)),
                HashPart::Str(note_in_id),
                HashPart::Json(&json!(simulation.asset_path)),
                HashPart::Json(&json!(simulation.hop_amounts)),
                HashPart::Int(amount_in as i128),
                HashPart::Int(simulation.amount_out as i128),
                HashPart::Int(network_fee as i128),
                HashPart::Json(&output_commitments(&outputs)),
            ],
            32,
        );
        let output_totals = note_totals_by_asset(&outputs)?;
        let expected_change = note_in.amount - amount_in - network_fee;
        let proof_system = "devnet-mock-amm-route-swap-proof".to_string();
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "kind": "amm_route_swap",
                "pool_ids": route_pool_ids,
                "route_root": route_root_for(&route_pool_ids, &simulation.asset_path, &simulation.hop_amounts),
                "route_hop_count": route_pool_ids.len(),
                "asset_path": simulation.asset_path,
                "hop_amounts": simulation.hop_amounts,
                "pool_hops": simulation.hop_views,
                "input_commitment": note_in.commitment,
                "nullifier": nullifier,
                "asset_in_id": note_in.asset_id,
                "asset_out_id": simulation.asset_path.last().cloned().unwrap_or_default(),
                "amount_in": amount_in,
                "amount_out": simulation.amount_out,
                "output_commitments": output_commitments(&outputs),
                "network_fee": network_fee,
                "encrypted_payload_hash": encrypted_payload_hash,
            }),
            &json!({
                "input_note": note_in.state_record(),
                "output_notes": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
                "output_totals": output_totals,
                "expected_change": expected_change,
            }),
        );
        let mut tx = AmmRouteSwap {
            pool_ids: route_pool_ids,
            spent_note_id: note_in_id.to_string(),
            nullifier,
            asset_path: simulation.asset_path,
            hop_amounts: simulation.hop_amounts,
            amount_in,
            amount_out: simulation.amount_out,
            output_notes: outputs,
            network_fee,
            encrypted_payload_hash,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        tx.authorization = sign_authorization(
            &tx.signer_label,
            "amm_route_swap",
            &tx.unsigned_record(true),
        );
        if !verify_authorization(
            &tx.signer_label,
            "amm_route_swap",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid AMM route swap authorization".to_string());
        }
        self.notes.remove(note_in_id);
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&tx.asset_in_id(), network_fee);
        for (pool_id, updated_pool) in simulation.updated_pools {
            self.pools.insert(pool_id, updated_pool);
        }
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        Ok(tx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_dark_pool_swap(
        &mut self,
        note_a_id: &str,
        note_b_id: &str,
        amount_a: u64,
        amount_b: u64,
        recipient_a_view_key: &str,
        recipient_b_view_key: &str,
        network_fee_a: u64,
        network_fee_b: u64,
        signer_a_label: Option<&str>,
        signer_b_label: Option<&str>,
        match_salt: Option<&str>,
    ) -> DefiResult<DarkPoolSwap> {
        if note_a_id == note_b_id {
            return Err("dark pool swap notes must be distinct".to_string());
        }
        if amount_a == 0 || amount_b == 0 {
            return Err("dark pool swap amounts must be positive".to_string());
        }
        let note_a = self.require_note(note_a_id)?.clone();
        let note_b = self.require_note(note_b_id)?.clone();
        let signer_a_label = signer_a_label.unwrap_or(&note_a.owner_view_key).to_string();
        let signer_b_label = signer_b_label.unwrap_or(&note_b.owner_view_key).to_string();
        if signer_a_label != note_a.owner_view_key {
            return Err("signer A does not own the dark pool note".to_string());
        }
        if signer_b_label != note_b.owner_view_key {
            return Err("signer B does not own the dark pool note".to_string());
        }
        if note_a.asset_id == note_b.asset_id {
            return Err("dark pool swap assets must be distinct".to_string());
        }
        let required_a = amount_a
            .checked_add(network_fee_a)
            .ok_or_else(|| "dark pool leg A amount overflow".to_string())?;
        let required_b = amount_b
            .checked_add(network_fee_b)
            .ok_or_else(|| "dark pool leg B amount overflow".to_string())?;
        if note_a.amount < required_a {
            return Err("dark pool leg A cannot cover amount plus fee".to_string());
        }
        if note_b.amount < required_b {
            return Err("dark pool leg B cannot cover amount plus fee".to_string());
        }
        let nullifier_a = note_nullifier(&note_a);
        let nullifier_b = note_nullifier(&note_b);
        if nullifier_a == nullifier_b {
            return Err("duplicate nullifier in transaction".to_string());
        }
        self.check_nullifier_available(&nullifier_a)?;
        self.check_nullifier_available(&nullifier_b)?;
        let mut output_notes = vec![
            Note::create(
                recipient_b_view_key,
                &note_a.asset_id,
                amount_a,
                self.next_nonce(),
            ),
            Note::create(
                recipient_a_view_key,
                &note_b.asset_id,
                amount_b,
                self.next_nonce(),
            ),
        ];
        let change_a = note_a.amount - amount_a - network_fee_a;
        let change_b = note_b.amount - amount_b - network_fee_b;
        if change_a != 0 {
            output_notes.push(Note::create(
                &note_a.owner_view_key,
                &note_a.asset_id,
                change_a,
                self.next_nonce(),
            ));
        }
        if change_b != 0 {
            output_notes.push(Note::create(
                &note_b.owner_view_key,
                &note_b.asset_id,
                change_b,
                self.next_nonce(),
            ));
        }
        let salt = match match_salt {
            Some(salt) => salt.to_string(),
            None => {
                let nonce = self.next_nonce();
                domain_hash("DARK-POOL-MATCH-SALT", &[HashPart::Int(nonce as i128)], 32)
            }
        };
        let encrypted_payload_hash = domain_hash(
            "DARK-POOL-SWAP-PAYLOAD",
            &[
                HashPart::Str(note_a_id),
                HashPart::Str(note_b_id),
                HashPart::Str(&note_a.asset_id),
                HashPart::Str(&note_b.asset_id),
                HashPart::Int(amount_a as i128),
                HashPart::Int(amount_b as i128),
                HashPart::Int(network_fee_a as i128),
                HashPart::Int(network_fee_b as i128),
                HashPart::Str(&dark_pool_recipient_a_commitment(recipient_a_view_key)),
                HashPart::Str(&dark_pool_recipient_b_commitment(recipient_b_view_key)),
                HashPart::Str(&salt),
                HashPart::Json(&output_commitments(&output_notes)),
            ],
            32,
        );
        let proof_system = "devnet-mock-dark-pool-swap-proof".to_string();
        let mut tx = DarkPoolSwap {
            spent_note_a_id: note_a_id.to_string(),
            spent_note_b_id: note_b_id.to_string(),
            nullifier_a,
            nullifier_b,
            asset_a_id: note_a.asset_id.clone(),
            asset_b_id: note_b.asset_id.clone(),
            amount_a,
            amount_b,
            recipient_a_view_key: recipient_a_view_key.to_string(),
            recipient_b_view_key: recipient_b_view_key.to_string(),
            network_fee_a,
            network_fee_b,
            match_salt: salt,
            output_notes,
            encrypted_payload_hash,
            signer_a_label,
            signer_b_label,
            authorization_a: empty_authorization(),
            authorization_b: empty_authorization(),
            proof_system,
            privacy_proof: build_privacy_proof("pending", &json!({}), &json!({})),
        };
        tx.privacy_proof = build_privacy_proof(
            &tx.proof_system,
            &json!({
                "kind": "dark_pool_swap",
                "trade_commitment": tx.trade_commitment(),
                "asset_pair_commitment": dark_pool_asset_pair_commitment(&tx.asset_a_id, &tx.asset_b_id),
                "nullifiers": [tx.nullifier_a, tx.nullifier_b],
                "input_commitments": [note_a.commitment, note_b.commitment],
                "output_commitments": output_commitments(&tx.output_notes),
                "encrypted_payload_hash": tx.encrypted_payload_hash,
            }),
            &json!({
                "input_notes": [note_a.state_record(), note_b.state_record()],
                "output_notes": tx.output_notes.iter().map(Note::state_record).collect::<Vec<_>>(),
                "asset_a_id": tx.asset_a_id,
                "asset_b_id": tx.asset_b_id,
                "amount_a": tx.amount_a,
                "amount_b": tx.amount_b,
                "recipient_a_commitment": dark_pool_recipient_a_commitment(&tx.recipient_a_view_key),
                "recipient_b_commitment": dark_pool_recipient_b_commitment(&tx.recipient_b_view_key),
                "network_fee_a": tx.network_fee_a,
                "network_fee_b": tx.network_fee_b,
                "match_salt": tx.match_salt,
            }),
        );
        tx.authorization_a = sign_authorization(
            &tx.signer_a_label,
            "dark_pool_swap",
            &tx.leg_authorization_payload("a")?,
        );
        tx.authorization_b = sign_authorization(
            &tx.signer_b_label,
            "dark_pool_swap",
            &tx.leg_authorization_payload("b")?,
        );
        if !verify_authorization(
            &tx.signer_a_label,
            "dark_pool_swap",
            &tx.leg_authorization_payload("a")?,
            &tx.authorization_a,
        ) || !verify_authorization(
            &tx.signer_b_label,
            "dark_pool_swap",
            &tx.leg_authorization_payload("b")?,
            &tx.authorization_b,
        ) {
            return Err("invalid dark pool swap authorization".to_string());
        }
        self.notes.remove(note_a_id);
        self.notes.remove(note_b_id);
        self.spent_nullifiers.push(tx.nullifier_a.clone());
        self.spent_nullifiers.push(tx.nullifier_b.clone());
        self.add_fee(&tx.asset_a_id, network_fee_a);
        self.add_fee(&tx.asset_b_id, network_fee_b);
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        Ok(tx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_lending_borrow(
        &mut self,
        market_id: &str,
        collateral_note_id: &str,
        collateral_amount: u64,
        borrow_amount: u64,
        owner_view_key: &str,
        borrow_fee: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<LendingBorrow> {
        let market = self.require_lending_market(market_id)?.clone();
        if market.status != "active" {
            return Err("lending market is not active".to_string());
        }
        let collateral_note = self.require_note(collateral_note_id)?.clone();
        let signer_label = signer_label
            .unwrap_or(&collateral_note.owner_view_key)
            .to_string();
        if signer_label != collateral_note.owner_view_key {
            return Err("signer does not own the lending collateral note".to_string());
        }
        if owner_view_key != collateral_note.owner_view_key {
            return Err("borrow owner must match collateral note owner".to_string());
        }
        if collateral_note.asset_id != market.collateral_asset_id {
            return Err("lending collateral asset mismatch".to_string());
        }
        if collateral_amount == 0 {
            return Err("lending collateral amount must be positive".to_string());
        }
        if borrow_amount == 0 {
            return Err("lending borrow amount must be positive".to_string());
        }
        let required = collateral_amount
            .checked_add(borrow_fee)
            .ok_or_else(|| "lending borrow amount overflow".to_string())?;
        if collateral_note.amount < required {
            return Err("collateral note cannot cover amount plus borrow fee".to_string());
        }
        let max_borrow = self.lending_max_borrow(&market, collateral_amount)?;
        if borrow_amount > max_borrow {
            return Err("borrow amount exceeds collateral factor".to_string());
        }
        let nullifier = note_nullifier(&collateral_note);
        self.check_nullifier_available(&nullifier)?;
        let terms_hash =
            lending_borrow_terms_hash(market_id, collateral_amount, borrow_amount, borrow_fee);
        let position_id = domain_hash(
            "LENDING-POSITION-ID",
            &[
                HashPart::Str(market_id),
                HashPart::Str(&nullifier),
                HashPart::Str(&terms_hash),
            ],
            32,
        );
        if self.lending_positions.contains_key(&position_id) {
            return Err("lending position already exists".to_string());
        }
        let mut outputs = vec![Note::create(
            owner_view_key,
            &market.debt_asset_id,
            borrow_amount,
            self.next_nonce(),
        )];
        let collateral_change = collateral_note.amount - collateral_amount - borrow_fee;
        if collateral_change != 0 {
            outputs.push(Note::create(
                owner_view_key,
                &market.collateral_asset_id,
                collateral_change,
                self.next_nonce(),
            ));
        }
        let proof_system = "devnet-mock-private-lending-borrow-proof".to_string();
        let oracle_price = self
            .market_oracle_feed(&market)?
            .map(OraclePriceFeed::public_record);
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "kind": "lending_borrow",
                "market": market.public_record(),
                "oracle_price": oracle_price,
                "input_commitment": collateral_note.commitment,
                "nullifier": nullifier,
                "position_id": position_id,
                "terms_hash": terms_hash,
                "output_commitments": output_commitments(&outputs),
            }),
            &json!({
                "collateral_note": collateral_note.state_record(),
                "output_notes": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
                "collateral_amount": collateral_amount,
                "borrow_amount": borrow_amount,
                "borrow_fee": borrow_fee,
                "max_borrow": max_borrow,
            }),
        );
        let mut tx = LendingBorrow {
            market_id: market_id.to_string(),
            spent_collateral_note_id: collateral_note_id.to_string(),
            nullifier,
            collateral_amount,
            borrow_amount,
            borrow_fee,
            position_id,
            output_notes: outputs,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        tx.authorization = sign_authorization(
            &tx.signer_label,
            "lending_borrow",
            &tx.unsigned_record(true),
        );
        if !verify_authorization(
            &tx.signer_label,
            "lending_borrow",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid lending borrow authorization".to_string());
        }
        let spent = self
            .notes
            .remove(collateral_note_id)
            .ok_or_else(|| "unknown or already spent collateral note".to_string())?;
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&market.collateral_asset_id, borrow_fee);
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        self.lending_positions.insert(
            tx.position_id.clone(),
            LendingPosition {
                position_id: tx.position_id.clone(),
                market_id: tx.market_id.clone(),
                owner_view_key: spent.owner_view_key,
                collateral_asset_id: market.collateral_asset_id.clone(),
                debt_asset_id: market.debt_asset_id.clone(),
                collateral_amount,
                debt_amount: borrow_amount,
                collateral_commitment: spent.commitment,
                debt_commitment: tx.output_notes[0].commitment.clone(),
                status: "active".to_string(),
                created_at_height: self.height,
                closed_at_height: 0,
            },
        );
        self.bump_lending_market_totals(
            market_id,
            collateral_amount as i128,
            borrow_amount as i128,
        )?;
        Ok(tx)
    }

    pub fn submit_lending_repay(
        &mut self,
        position_id: &str,
        debt_note_id: &str,
        repay_fee: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<LendingRepay> {
        let position = self.require_lending_position(position_id)?.clone();
        if position.status != "active" {
            return Err("lending position is not active".to_string());
        }
        let market = self.require_lending_market(&position.market_id)?.clone();
        let debt_note = self.require_note(debt_note_id)?.clone();
        let signer_label = signer_label
            .unwrap_or(&debt_note.owner_view_key)
            .to_string();
        if signer_label != position.owner_view_key {
            return Err("signer does not own the lending position".to_string());
        }
        if debt_note.owner_view_key != position.owner_view_key {
            return Err("debt note owner does not match lending position".to_string());
        }
        if debt_note.asset_id != position.debt_asset_id {
            return Err("lending repay debt asset mismatch".to_string());
        }
        let required = position
            .debt_amount
            .checked_add(repay_fee)
            .ok_or_else(|| "lending repay amount overflow".to_string())?;
        if debt_note.amount < required {
            return Err("debt note cannot cover repayment plus fee".to_string());
        }
        let nullifier = note_nullifier(&debt_note);
        self.check_nullifier_available(&nullifier)?;
        let debt_change = debt_note.amount - position.debt_amount - repay_fee;
        let mut outputs = vec![Note::create(
            &position.owner_view_key,
            &position.collateral_asset_id,
            position.collateral_amount,
            self.next_nonce(),
        )];
        if debt_change != 0 {
            outputs.push(Note::create(
                &position.owner_view_key,
                &position.debt_asset_id,
                debt_change,
                self.next_nonce(),
            ));
        }
        let proof_system = "devnet-mock-private-lending-repay-proof".to_string();
        let terms_hash = lending_repay_terms_hash(position_id, repay_fee, &outputs);
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "kind": "lending_repay",
                "market": market.public_record(),
                "position": position.public_record(),
                "input_commitment": debt_note.commitment,
                "nullifier": nullifier,
                "terms_hash": terms_hash,
                "output_commitments": output_commitments(&outputs),
            }),
            &json!({
                "debt_note": debt_note.state_record(),
                "output_notes": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
                "position": position.state_record(),
                "repay_fee": repay_fee,
                "debt_change": debt_change,
            }),
        );
        let mut tx = LendingRepay {
            position_id: position_id.to_string(),
            spent_debt_note_id: debt_note_id.to_string(),
            nullifier,
            repay_fee,
            output_notes: outputs,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        tx.authorization =
            sign_authorization(&tx.signer_label, "lending_repay", &tx.unsigned_record(true));
        if !verify_authorization(
            &tx.signer_label,
            "lending_repay",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid lending repay authorization".to_string());
        }
        self.notes
            .remove(debt_note_id)
            .ok_or_else(|| "unknown or already spent debt note".to_string())?;
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&position.debt_asset_id, repay_fee);
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        self.close_lending_position(position_id, "repaid")?;
        self.bump_lending_market_totals(
            &position.market_id,
            -(position.collateral_amount as i128),
            -(position.debt_amount as i128),
        )?;
        Ok(tx)
    }

    pub fn submit_lending_liquidation(
        &mut self,
        position_id: &str,
        debt_note_id: &str,
        liquidator_view_key: &str,
        liquidation_fee: u64,
        signer_label: Option<&str>,
    ) -> DefiResult<LendingLiquidation> {
        if liquidator_view_key.is_empty() {
            return Err("liquidator view key is required".to_string());
        }
        let position = self.require_lending_position(position_id)?.clone();
        if position.status != "active" {
            return Err("lending position is not active".to_string());
        }
        let market = self.require_lending_market(&position.market_id)?.clone();
        if market.status != "active" {
            return Err("lending market is not active".to_string());
        }
        let debt_note = self.require_note(debt_note_id)?.clone();
        let signer_label = signer_label
            .unwrap_or(&debt_note.owner_view_key)
            .to_string();
        if signer_label != debt_note.owner_view_key {
            return Err("signer does not own the liquidation debt note".to_string());
        }
        if debt_note.asset_id != position.debt_asset_id {
            return Err("lending liquidation debt asset mismatch".to_string());
        }
        let (collateral_value, liquidation_limit) =
            self.lending_liquidation_limit(&market, position.collateral_amount)?;
        if position.debt_amount <= liquidation_limit {
            return Err("lending position is not liquidatable".to_string());
        }
        let required = position
            .debt_amount
            .checked_add(liquidation_fee)
            .ok_or_else(|| "lending liquidation amount overflow".to_string())?;
        if debt_note.amount < required {
            return Err("debt note cannot cover liquidation plus fee".to_string());
        }
        let nullifier = note_nullifier(&debt_note);
        self.check_nullifier_available(&nullifier)?;
        let debt_change = debt_note.amount - position.debt_amount - liquidation_fee;
        let mut outputs = vec![Note::create(
            liquidator_view_key,
            &position.collateral_asset_id,
            position.collateral_amount,
            self.next_nonce(),
        )];
        if debt_change != 0 {
            outputs.push(Note::create(
                &debt_note.owner_view_key,
                &position.debt_asset_id,
                debt_change,
                self.next_nonce(),
            ));
        }
        let liquidator_commitment = lending_liquidator_commitment(liquidator_view_key);
        let terms_hash = lending_liquidation_terms_hash(
            position_id,
            liquidation_fee,
            &liquidator_commitment,
            &outputs,
        );
        let oracle_price = self
            .market_oracle_feed(&market)?
            .map(OraclePriceFeed::public_record);
        let proof_system = "devnet-mock-private-lending-liquidation-proof".to_string();
        let privacy_proof = build_privacy_proof(
            &proof_system,
            &json!({
                "kind": "lending_liquidation",
                "market": market.public_record(),
                "oracle_price": oracle_price,
                "position": position.public_record(),
                "input_commitment": debt_note.commitment,
                "nullifier": nullifier,
                "liquidator_commitment": liquidator_commitment,
                "terms_hash": terms_hash,
                "output_commitments": output_commitments(&outputs),
            }),
            &json!({
                "debt_note": debt_note.state_record(),
                "output_notes": outputs.iter().map(Note::state_record).collect::<Vec<_>>(),
                "position": position.state_record(),
                "collateral_value": collateral_value,
                "liquidation_limit": liquidation_limit,
                "liquidation_fee": liquidation_fee,
                "debt_change": debt_change,
            }),
        );
        let mut tx = LendingLiquidation {
            position_id: position_id.to_string(),
            spent_debt_note_id: debt_note_id.to_string(),
            nullifier,
            liquidation_fee,
            liquidator_view_key: liquidator_view_key.to_string(),
            output_notes: outputs,
            signer_label,
            authorization: empty_authorization(),
            proof_system,
            privacy_proof,
        };
        tx.authorization = sign_authorization(
            &tx.signer_label,
            "lending_liquidation",
            &tx.unsigned_record(true),
        );
        if !verify_authorization(
            &tx.signer_label,
            "lending_liquidation",
            &tx.unsigned_record(true),
            &tx.authorization,
        ) {
            return Err("invalid lending liquidation authorization".to_string());
        }
        self.notes
            .remove(debt_note_id)
            .ok_or_else(|| "unknown or already spent debt note".to_string())?;
        self.spent_nullifiers.push(tx.nullifier.clone());
        self.add_fee(&position.debt_asset_id, liquidation_fee);
        for output in &tx.output_notes {
            self.notes.insert(output.note_id.clone(), output.clone());
        }
        self.close_lending_position(position_id, "liquidated")?;
        self.bump_lending_market_totals(
            &position.market_id,
            -(position.collateral_amount as i128),
            -(position.debt_amount as i128),
        )?;
        Ok(tx)
    }

    pub fn asset_root(&self) -> String {
        let leaves = self
            .assets
            .values()
            .map(|asset| {
                let supply = self
                    .asset_supplies
                    .get(&asset.asset_id)
                    .cloned()
                    .unwrap_or_else(|| AssetSupply::new(&asset.asset_id));
                json!({
                    "asset": asset.public_record(),
                    "supply": supply.public_record(),
                })
            })
            .collect::<Vec<_>>();
        merkle_root("ASSET", &leaves)
    }

    pub fn note_root(&self) -> String {
        let leaves = self
            .notes
            .values()
            .map(|note| note.commitment.clone())
            .collect::<Vec<_>>();
        let mut leaves = leaves;
        leaves.sort();
        let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root("NOTE", &leaves)
    }

    pub fn nullifier_root(&self) -> String {
        let mut leaves = self.spent_nullifiers.clone();
        leaves.sort();
        let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root("NULLIFIER", &leaves)
    }

    pub fn amm_pool_root(&self) -> String {
        let leaves = self
            .pools
            .values()
            .map(AmmPool::public_record)
            .collect::<Vec<_>>();
        merkle_root("AMM-POOL", &leaves)
    }

    pub fn oracle_root(&self) -> String {
        merkle_root(
            "ORACLE-PRICE",
            &self
                .oracle_prices
                .values()
                .map(OraclePriceFeed::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lending_market_root(&self) -> String {
        merkle_root(
            "LENDING-MARKET",
            &self
                .lending_markets
                .values()
                .map(LendingMarket::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lending_position_root(&self) -> String {
        merkle_root(
            "LENDING-POSITION",
            &self
                .lending_positions
                .values()
                .map(LendingPosition::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lending_root(&self) -> String {
        merkle_root(
            "LENDING",
            &[json!({
                "lending_market_count": self.lending_markets.len(),
                "lending_market_root": self.lending_market_root(),
                "lending_position_count": self.lending_positions.len(),
                "lending_position_root": self.lending_position_root(),
                "oracle_root": self.oracle_root(),
            })],
        )
    }

    pub fn sealed_swap_order_commitment_root(&self) -> String {
        merkle_root(
            "SEALED-SWAP-ORDER-COMMITMENT",
            &self
                .sealed_swap_order_commitments
                .values()
                .map(SealedSwapOrderCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sealed_swap_solver_bid_root(&self) -> String {
        merkle_root(
            "SEALED-SWAP-SOLVER-BID",
            &self
                .sealed_swap_solver_bids
                .values()
                .map(SealedSwapSolverBid::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sealed_swap_auction_root(&self) -> String {
        merkle_root(
            "SEALED-SWAP-AUCTION",
            &[json!({
                "sealed_swap_order_commitment_count": self.sealed_swap_order_commitments.len(),
                "sealed_swap_order_commitment_root": self.sealed_swap_order_commitment_root(),
                "sealed_swap_solver_bid_count": self.sealed_swap_solver_bids.len(),
                "sealed_swap_solver_bid_root": self.sealed_swap_solver_bid_root(),
                "sealed_swap_settlement_receipt_count": self.sealed_swap_settlement_receipts.len(),
                "sealed_swap_settlement_receipt_root": self.sealed_swap_settlement_receipt_root(),
            })],
        )
    }

    pub fn sealed_swap_settlement_receipt_root(&self) -> String {
        merkle_root(
            "SEALED-SWAP-SETTLEMENT-RECEIPT",
            &self
                .sealed_swap_settlement_receipts
                .values()
                .map(SealedSwapSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn fee_root(&self) -> String {
        let leaves = self
            .fees_collected
            .iter()
            .map(|(asset_id, amount)| json!([asset_id, amount]))
            .collect::<Vec<_>>();
        merkle_root("FEE", &leaves)
    }

    pub fn wallet_notes(&self, owner_view_key: &str) -> Vec<Value> {
        self.notes
            .values()
            .filter(|note| note.owner_view_key == owner_view_key)
            .map(Note::wallet_record)
            .collect()
    }

    fn verify_sealed_swap_intent(&self, intent: &SealedSwapIntent) -> DefiResult<()> {
        let pool = self.require_pool(&intent.pool_id)?;
        self.require_asset(&intent.asset_in_id)?;
        self.require_asset(&intent.asset_out_id)?;
        if intent.amount_in == 0 {
            return Err("sealed swap intent amount must be positive".to_string());
        }
        let expected_asset_out = sealed_swap_output_asset(pool, &intent.asset_in_id)?;
        if intent.asset_out_id != expected_asset_out {
            return Err("sealed swap intent output asset mismatch".to_string());
        }
        if intent.signer_label.is_empty() {
            return Err("sealed swap intent is missing signer label".to_string());
        }
        if !verify_authorization(
            &intent.signer_label,
            "sealed_amm_swap_intent",
            &intent.unsigned_record(),
            &intent.authorization,
        ) {
            return Err("invalid sealed swap intent authorization".to_string());
        }
        Ok(())
    }

    fn verify_amm_sealed_batch_swap(&self, tx: &AmmSealedBatchSwap) -> DefiResult<()> {
        if tx.fills.is_empty() {
            return Err("sealed batch swap requires fills".to_string());
        }
        if tx.solver_label.is_empty() {
            return Err("sealed swap solver label is required".to_string());
        }
        let pool = self.require_pool(&tx.pool_id)?;
        let (reserve_in, reserve_out, expected_asset_out) = amm_asset_view(pool, &tx.asset_in_id)?;
        if tx.asset_out_id != expected_asset_out {
            return Err("sealed batch swap output asset mismatch".to_string());
        }
        let mut total_amount_in = 0_u64;
        let mut total_amount_out = 0_u64;
        let mut network_fee_total = 0_u64;
        let mut nullifiers = Vec::with_capacity(tx.fills.len());
        for fill in &tx.fills {
            self.verify_sealed_swap_intent(&fill.intent)?;
            if fill.intent.pool_id != tx.pool_id {
                return Err("sealed batch swap fill pool mismatch".to_string());
            }
            if fill.intent.asset_in_id != tx.asset_in_id
                || fill.intent.asset_out_id != tx.asset_out_id
            {
                return Err("sealed batch swap fill asset mismatch".to_string());
            }
            if fill.amount_out < fill.intent.min_amount_out {
                return Err("sealed swap output below minimum".to_string());
            }
            if fill.output_note.asset_id != tx.asset_out_id
                || fill.output_note.amount != fill.amount_out
            {
                return Err("sealed swap output note mismatch".to_string());
            }
            if let Some(change_note) = &fill.change_note {
                if change_note.asset_id != tx.asset_in_id {
                    return Err("sealed swap change note asset mismatch".to_string());
                }
            }
            total_amount_in = total_amount_in
                .checked_add(fill.intent.amount_in)
                .ok_or_else(|| "sealed batch swap total input overflow".to_string())?;
            total_amount_out = total_amount_out
                .checked_add(fill.amount_out)
                .ok_or_else(|| "sealed batch swap total output overflow".to_string())?;
            network_fee_total = network_fee_total
                .checked_add(fill.intent.network_fee)
                .ok_or_else(|| "sealed batch swap network fee overflow".to_string())?;
            nullifiers.push(fill.intent.nullifier.clone());
        }
        ensure_distinct(&nullifiers, "duplicate nullifier in transaction")?;
        if total_amount_in != tx.total_amount_in {
            return Err("sealed batch swap input total mismatch".to_string());
        }
        if total_amount_out != tx.total_amount_out {
            return Err("sealed batch swap output total mismatch".to_string());
        }
        if network_fee_total != tx.network_fee_total {
            return Err("sealed batch swap fee total mismatch".to_string());
        }
        if tx.total_amount_out != amm_output_amount(pool, reserve_in, reserve_out, total_amount_in)?
        {
            return Err("sealed batch swap clearing amount mismatch".to_string());
        }
        if tx.commitment_ids.len() != tx.fills.len() {
            return Err("sealed batch swap commitment count mismatch".to_string());
        }
        if tx.commitment_reveal_secrets.len() != tx.fills.len() {
            return Err("sealed batch swap reveal secret count mismatch".to_string());
        }
        self.verify_sealed_swap_solver_bid_for_tx(tx)?;
        Ok(())
    }

    fn verify_sealed_swap_solver_bid_for_tx(&self, tx: &AmmSealedBatchSwap) -> DefiResult<()> {
        if tx.solver_bid_id.is_empty() {
            return Ok(());
        }
        let bid = self
            .sealed_swap_solver_bids
            .get(&tx.solver_bid_id)
            .ok_or_else(|| "unknown sealed swap solver bid".to_string())?;
        self.verify_sealed_swap_solver_bid(bid)?;
        if bid.status != "active" {
            return Err("sealed swap solver bid is not active".to_string());
        }
        if bid.expires_height < self.height {
            return Err("sealed swap solver bid has expired".to_string());
        }
        if bid.solver_label != tx.solver_label {
            return Err("sealed swap solver bid solver mismatch".to_string());
        }
        if self.sealed_swap_matching_bid_key(bid) != self.sealed_swap_tx_bid_key(tx) {
            return Err("sealed swap solver bid batch mismatch".to_string());
        }
        if tx.total_amount_out < bid.quoted_amount_out {
            return Err("sealed swap output below solver bid".to_string());
        }
        let better_bid_exists = self
            .matching_active_sealed_swap_solver_bid_ids(tx)
            .into_iter()
            .filter(|bid_id| bid_id != &bid.bid_id)
            .filter_map(|bid_id| self.sealed_swap_solver_bids.get(&bid_id))
            .any(|other| other.quoted_amount_out > bid.quoted_amount_out);
        if better_bid_exists {
            return Err("better sealed swap solver bid is available".to_string());
        }
        Ok(())
    }

    fn sealed_swap_matching_bid_key(
        &self,
        bid: &SealedSwapSolverBid,
    ) -> (String, String, String, String, u64, u64) {
        (
            bid.pool_id.clone(),
            bid.batch_commitment_root.clone(),
            bid.asset_in_id.clone(),
            bid.asset_out_id.clone(),
            bid.total_amount_in,
            bid.network_fee_total,
        )
    }

    fn sealed_swap_tx_bid_key(
        &self,
        tx: &AmmSealedBatchSwap,
    ) -> (String, String, String, String, u64, u64) {
        (
            tx.pool_id.clone(),
            tx.commitment_root(),
            tx.asset_in_id.clone(),
            tx.asset_out_id.clone(),
            tx.total_amount_in,
            tx.network_fee_total,
        )
    }

    fn matching_active_sealed_swap_solver_bid_ids(&self, tx: &AmmSealedBatchSwap) -> Vec<String> {
        let key = self.sealed_swap_tx_bid_key(tx);
        self.sealed_swap_solver_bids
            .values()
            .filter(|bid| {
                bid.status == "active"
                    && bid.expires_height >= self.height
                    && self.sealed_swap_matching_bid_key(bid) == key
            })
            .map(|bid| bid.bid_id.clone())
            .collect()
    }

    fn mark_sealed_swap_commitments_revealed(&mut self, tx: &AmmSealedBatchSwap) -> DefiResult<()> {
        for (commitment_id, fill) in tx.commitment_ids.iter().zip(tx.fills.iter()) {
            let mut commitment = self
                .sealed_swap_order_commitments
                .get(commitment_id)
                .cloned()
                .ok_or_else(|| "unknown sealed swap commitment".to_string())?;
            if commitment.status != "active" {
                return Err("sealed swap commitment is not active".to_string());
            }
            commitment.status = "revealed".to_string();
            commitment.revealed_intent_hash = fill.intent.intent_hash();
            commitment.revealed_at_height = self.height;
            self.verify_sealed_swap_order_commitment(&commitment)?;
            self.sealed_swap_order_commitments
                .insert(commitment_id.clone(), commitment);
        }
        Ok(())
    }

    fn mark_sealed_swap_solver_bids_settled(&mut self, tx: &AmmSealedBatchSwap) -> DefiResult<()> {
        if tx.solver_bid_id.is_empty() {
            return Ok(());
        }
        let tx_public_hash = sealed_swap_tx_public_hash(tx);
        let bid_ids = self.matching_active_sealed_swap_solver_bid_ids(tx);
        for bid_id in bid_ids {
            let mut bid = self
                .sealed_swap_solver_bids
                .get(&bid_id)
                .cloned()
                .ok_or_else(|| "unknown sealed swap solver bid".to_string())?;
            bid.status = if bid.bid_id == tx.solver_bid_id {
                "won".to_string()
            } else {
                "lost".to_string()
            };
            bid.settled_tx_public_hash = tx_public_hash.clone();
            bid.settled_at_height = self.height;
            self.verify_sealed_swap_solver_bid(&bid)?;
            self.sealed_swap_solver_bids.insert(bid_id, bid);
        }
        Ok(())
    }

    fn build_sealed_swap_settlement_receipt(
        &self,
        tx: &AmmSealedBatchSwap,
        pool_before: &AmmPool,
        pool_after: &AmmPool,
    ) -> DefiResult<SealedSwapSettlementReceipt> {
        if tx.solver_label.is_empty() {
            return Err("sealed swap solver label is required".to_string());
        }
        let (before_in, before_out, before_asset_out) =
            amm_asset_view(pool_before, &tx.asset_in_id)?;
        let (after_in, after_out, after_asset_out) = amm_asset_view(pool_after, &tx.asset_in_id)?;
        if before_asset_out != tx.asset_out_id || after_asset_out != tx.asset_out_id {
            return Err("sealed swap receipt asset mismatch".to_string());
        }
        let pool_before_root = sealed_swap_pool_view_root(
            &pool_before.pool_id,
            &tx.asset_in_id,
            &tx.asset_out_id,
            before_in,
            before_out,
            pool_before.fee_bps,
            &pool_before.curve,
        );
        let pool_after_root = sealed_swap_pool_view_root(
            &pool_after.pool_id,
            &tx.asset_in_id,
            &tx.asset_out_id,
            after_in,
            after_out,
            pool_after.fee_bps,
            &pool_after.curve,
        );
        let (fill_root, minimum_root, surplus_root, total_surplus) = sealed_swap_receipt_roots(tx)?;
        let tx_public_hash = sealed_swap_tx_public_hash(tx);
        let route_commitment = sealed_swap_route_commitment(
            &tx.pool_id,
            &tx.asset_in_id,
            &tx.asset_out_id,
            &pool_before_root,
            &pool_after_root,
        );
        let receipt_id = sealed_swap_settlement_receipt_id(
            self.height,
            &tx_public_hash,
            &tx.intent_root(),
            &tx.solver_label,
        );
        let mut receipt = SealedSwapSettlementReceipt {
            receipt_id,
            block_height: self.height,
            tx_public_hash,
            pool_id: tx.pool_id.clone(),
            solver_label: tx.solver_label.clone(),
            intent_count: tx.fills.len() as u64,
            intent_root: tx.intent_root(),
            route_commitment,
            asset_in_id: tx.asset_in_id.clone(),
            asset_out_id: tx.asset_out_id.clone(),
            total_amount_in: tx.total_amount_in,
            total_amount_out: tx.total_amount_out,
            network_fee_total: tx.network_fee_total,
            pool_fee_bps: pool_before.fee_bps,
            pool_before_root,
            pool_after_root,
            pool_before_reserve_in: before_in,
            pool_before_reserve_out: before_out,
            pool_after_reserve_in: after_in,
            pool_after_reserve_out: after_out,
            fill_commitment_root: fill_root,
            minimum_output_root: minimum_root,
            surplus_commitment_root: surplus_root,
            total_surplus_amount: total_surplus,
            clearing_price_numerator: tx.total_amount_out,
            clearing_price_denominator: tx.total_amount_in,
            pool_curve: pool_before.curve.clone(),
            solver_bid_id: tx.solver_bid_id.clone(),
            clearing_price_commitment_root: String::new(),
            aggregate_surplus_commitment_root: String::new(),
            authorization: empty_authorization(),
        };
        receipt.clearing_price_commitment_root = receipt.expected_clearing_price_commitment_root();
        receipt.aggregate_surplus_commitment_root =
            receipt.expected_aggregate_surplus_commitment_root();
        receipt.authorization = sign_authorization(
            &receipt.solver_label,
            "sealed_swap_settlement_receipt",
            &receipt.unsigned_record(),
        );
        Ok(receipt)
    }

    fn verify_sealed_swap_settlement_receipt(
        &self,
        receipt: &SealedSwapSettlementReceipt,
        tx: &AmmSealedBatchSwap,
        pool_before: &AmmPool,
        pool_after: &AmmPool,
    ) -> DefiResult<()> {
        if receipt.tx_public_hash != sealed_swap_tx_public_hash(tx) {
            return Err("sealed swap receipt transaction mismatch".to_string());
        }
        if receipt.pool_id != tx.pool_id
            || receipt.solver_label != tx.solver_label
            || receipt.solver_bid_id != tx.solver_bid_id
            || receipt.intent_count != tx.fills.len() as u64
            || receipt.intent_root != tx.intent_root()
            || receipt.asset_in_id != tx.asset_in_id
            || receipt.asset_out_id != tx.asset_out_id
            || receipt.total_amount_in != tx.total_amount_in
            || receipt.total_amount_out != tx.total_amount_out
            || receipt.network_fee_total != tx.network_fee_total
        {
            return Err("sealed swap receipt tx fields mismatch".to_string());
        }
        if !receipt.solver_bid_id.is_empty() {
            let bid = self
                .sealed_swap_solver_bids
                .get(&receipt.solver_bid_id)
                .ok_or_else(|| "sealed swap receipt missing solver bid".to_string())?;
            self.verify_sealed_swap_solver_bid(bid)?;
            if bid.status != "won" {
                return Err("sealed swap receipt solver bid was not won".to_string());
            }
            if bid.settled_tx_public_hash != receipt.tx_public_hash
                || bid.settled_at_height != receipt.block_height
                || self.sealed_swap_matching_bid_key(bid) != self.sealed_swap_tx_bid_key(tx)
            {
                return Err("sealed swap receipt solver bid mismatch".to_string());
            }
            if bid.quoted_amount_out > receipt.total_amount_out {
                return Err("sealed swap receipt below solver bid".to_string());
            }
        }
        let expected_after_in = receipt
            .pool_before_reserve_in
            .checked_add(tx.total_amount_in)
            .ok_or_else(|| "sealed swap receipt reserve-in overflow".to_string())?;
        let expected_after_out = receipt
            .pool_before_reserve_out
            .checked_sub(tx.total_amount_out)
            .ok_or_else(|| "sealed swap receipt reserve-out underflow".to_string())?;
        if receipt.pool_after_reserve_in != expected_after_in
            || receipt.pool_after_reserve_out != expected_after_out
        {
            return Err("sealed swap receipt reserve mismatch".to_string());
        }
        if receipt.pool_curve != pool_before.curve || receipt.pool_curve != pool_after.curve {
            return Err("sealed swap receipt pool curve mismatch".to_string());
        }
        let expected_total_out = amm_output_amount(
            pool_before,
            receipt.pool_before_reserve_in,
            receipt.pool_before_reserve_out,
            receipt.total_amount_in,
        )?;
        if receipt.total_amount_out != expected_total_out {
            return Err("sealed swap receipt clearing amount mismatch".to_string());
        }
        let expected_before_root = sealed_swap_pool_view_root(
            &receipt.pool_id,
            &receipt.asset_in_id,
            &receipt.asset_out_id,
            receipt.pool_before_reserve_in,
            receipt.pool_before_reserve_out,
            receipt.pool_fee_bps,
            &receipt.pool_curve,
        );
        let expected_after_root = sealed_swap_pool_view_root(
            &receipt.pool_id,
            &receipt.asset_in_id,
            &receipt.asset_out_id,
            receipt.pool_after_reserve_in,
            receipt.pool_after_reserve_out,
            receipt.pool_fee_bps,
            &receipt.pool_curve,
        );
        if receipt.pool_before_root != expected_before_root
            || receipt.pool_after_root != expected_after_root
        {
            return Err("sealed swap receipt pool root mismatch".to_string());
        }
        let expected_route = sealed_swap_route_commitment(
            &receipt.pool_id,
            &receipt.asset_in_id,
            &receipt.asset_out_id,
            &receipt.pool_before_root,
            &receipt.pool_after_root,
        );
        if receipt.route_commitment != expected_route {
            return Err("sealed swap receipt route mismatch".to_string());
        }
        let (fill_root, minimum_root, surplus_root, total_surplus) = sealed_swap_receipt_roots(tx)?;
        if receipt.fill_commitment_root != fill_root
            || receipt.minimum_output_root != minimum_root
            || receipt.surplus_commitment_root != surplus_root
            || receipt.total_surplus_amount != total_surplus
        {
            return Err("sealed swap receipt fill root mismatch".to_string());
        }
        if receipt.clearing_price_numerator != tx.total_amount_out
            || receipt.clearing_price_denominator != tx.total_amount_in
            || receipt.clearing_price_commitment_root
                != receipt.expected_clearing_price_commitment_root()
            || receipt.aggregate_surplus_commitment_root
                != receipt.expected_aggregate_surplus_commitment_root()
        {
            return Err("sealed swap receipt clearing commitment mismatch".to_string());
        }
        let expected_receipt_id = sealed_swap_settlement_receipt_id(
            receipt.block_height,
            &receipt.tx_public_hash,
            &receipt.intent_root,
            &receipt.solver_label,
        );
        if receipt.receipt_id != expected_receipt_id {
            return Err("sealed swap receipt id mismatch".to_string());
        }
        if !verify_authorization(
            &receipt.solver_label,
            "sealed_swap_settlement_receipt",
            &receipt.unsigned_record(),
            &receipt.authorization,
        ) {
            return Err("invalid sealed swap settlement receipt authorization".to_string());
        }
        Ok(())
    }

    fn verify_sealed_swap_order_commitment(
        &self,
        commitment: &SealedSwapOrderCommitment,
    ) -> DefiResult<()> {
        self.require_pool(&commitment.pool_id)?;
        self.require_asset(&commitment.asset_in_id)?;
        self.require_asset(&commitment.asset_out_id)?;
        if commitment.expires_height <= commitment.min_reveal_height {
            return Err("sealed swap commitment expiry is invalid".to_string());
        }
        if !matches!(
            commitment.status.as_str(),
            "active" | "revealed" | "expired"
        ) {
            return Err("sealed swap commitment status is invalid".to_string());
        }
        if commitment.signer_label.is_empty() {
            return Err("sealed swap commitment is missing signer label".to_string());
        }
        if commitment.owner_commitment != sealed_swap_owner_commitment(&commitment.signer_label) {
            return Err("sealed swap commitment owner mismatch".to_string());
        }
        let expected_id = sealed_swap_order_commitment_id(
            &commitment.pool_id,
            &commitment.asset_in_id,
            &commitment.asset_out_id,
            &commitment.owner_commitment,
            &commitment.order_commitment,
            commitment.min_reveal_height,
            commitment.expires_height,
        );
        if commitment.commitment_id != expected_id {
            return Err("sealed swap commitment id mismatch".to_string());
        }
        if commitment.status == "active" {
            if !commitment.revealed_intent_hash.is_empty() || commitment.revealed_at_height != 0 {
                return Err("active sealed swap commitment cannot be revealed".to_string());
            }
        } else if commitment.status == "revealed" {
            if commitment.revealed_intent_hash.is_empty() {
                return Err("sealed swap commitment missing revealed intent".to_string());
            }
            if commitment.revealed_at_height < commitment.min_reveal_height {
                return Err("sealed swap commitment revealed too early".to_string());
            }
        } else if !commitment.revealed_intent_hash.is_empty() || commitment.revealed_at_height != 0
        {
            return Err("expired sealed swap commitment cannot be revealed".to_string());
        }
        if !verify_authorization(
            &commitment.signer_label,
            "sealed_swap_order_commitment",
            &commitment.unsigned_record(),
            &commitment.authorization,
        ) {
            return Err("invalid sealed swap commitment authorization".to_string());
        }
        Ok(())
    }

    fn verify_sealed_swap_solver_bid(&self, bid: &SealedSwapSolverBid) -> DefiResult<()> {
        self.require_pool(&bid.pool_id)?;
        self.require_asset(&bid.asset_in_id)?;
        self.require_asset(&bid.asset_out_id)?;
        if !matches!(bid.status.as_str(), "active" | "won" | "lost" | "expired") {
            return Err("sealed swap solver bid status is invalid".to_string());
        }
        if bid.total_amount_in == 0 {
            return Err("sealed swap solver bid input must be positive".to_string());
        }
        if bid.quoted_amount_out == 0 {
            return Err("sealed swap solver bid output must be positive".to_string());
        }
        if bid.status == "active" {
            if !bid.settled_tx_public_hash.is_empty() || bid.settled_at_height != 0 {
                return Err("active sealed swap solver bid cannot be settled".to_string());
            }
        } else if bid.status == "won" || bid.status == "lost" {
            if bid.settled_tx_public_hash.is_empty() {
                return Err("settled sealed swap solver bid missing transaction".to_string());
            }
        } else if !bid.settled_tx_public_hash.is_empty() || bid.settled_at_height != 0 {
            return Err("expired sealed swap solver bid cannot be settled".to_string());
        }
        let expected_id = sealed_swap_solver_bid_id(
            &bid.pool_id,
            &bid.solver_label,
            &bid.batch_commitment_root,
            &bid.asset_in_id,
            &bid.asset_out_id,
            bid.total_amount_in,
            bid.quoted_amount_out,
            bid.network_fee_total,
            bid.expires_height,
        );
        if bid.bid_id != expected_id {
            return Err("sealed swap solver bid id mismatch".to_string());
        }
        if !verify_authorization(
            &bid.solver_label,
            "sealed_swap_solver_bid",
            &bid.unsigned_record(),
            &bid.authorization,
        ) {
            return Err("invalid sealed swap solver bid authorization".to_string());
        }
        Ok(())
    }

    fn require_asset(&self, asset_id: &str) -> DefiResult<&Asset> {
        self.assets
            .get(asset_id)
            .ok_or_else(|| "unknown asset".to_string())
    }

    fn require_note(&self, note_id: &str) -> DefiResult<&Note> {
        self.notes
            .get(note_id)
            .ok_or_else(|| "unknown or already spent note".to_string())
    }

    fn require_pool(&self, pool_id: &str) -> DefiResult<&AmmPool> {
        self.pools
            .get(pool_id)
            .ok_or_else(|| "unknown AMM pool".to_string())
    }

    fn require_lending_market(&self, market_id: &str) -> DefiResult<&LendingMarket> {
        self.lending_markets
            .get(market_id)
            .ok_or_else(|| "unknown lending market".to_string())
    }

    fn require_lending_position(&self, position_id: &str) -> DefiResult<&LendingPosition> {
        self.lending_positions
            .get(position_id)
            .ok_or_else(|| "unknown lending position".to_string())
    }

    fn simulate_amm_route(
        &self,
        pool_ids: &[String],
        asset_in_id: &str,
        amount_in: u64,
    ) -> DefiResult<AmmRouteSimulation> {
        if pool_ids.is_empty() {
            return Err("route swap requires at least one pool".to_string());
        }
        if pool_ids.len() > 4 {
            return Err("route swap supports at most four hops".to_string());
        }
        if amount_in == 0 {
            return Err("route swap amount_in must be positive".to_string());
        }
        let mut virtual_pools = BTreeMap::<String, AmmPool>::new();
        let mut asset_path = vec![asset_in_id.to_string()];
        let mut hop_amounts = Vec::<u64>::new();
        let mut hop_views = Vec::<Value>::new();
        let mut current_asset = asset_in_id.to_string();
        let mut current_amount = amount_in;

        for pool_id in pool_ids {
            let pool = virtual_pools
                .get(pool_id)
                .cloned()
                .or_else(|| self.pools.get(pool_id).cloned())
                .ok_or_else(|| "unknown AMM pool".to_string())?;
            let (reserve_in, reserve_out, asset_out_id) = amm_asset_view(&pool, &current_asset)?;
            if reserve_in == 0 || reserve_out == 0 {
                return Err("pool has no liquidity".to_string());
            }
            let amount_out = amm_output_amount(&pool, reserve_in, reserve_out, current_amount)?;
            if amount_out == 0 {
                return Err("route swap outputs zero".to_string());
            }
            let updated_pool =
                updated_pool_for_swap(&pool, &current_asset, current_amount, amount_out)?;
            hop_views.push(json!({
                "pool_before": pool.public_record(),
                "pool_after": updated_pool.public_record(),
                "asset_in_id": current_asset,
                "asset_out_id": asset_out_id,
                "amount_in": current_amount,
                "amount_out": amount_out,
            }));
            virtual_pools.insert(pool_id.clone(), updated_pool);
            current_asset = asset_out_id;
            current_amount = amount_out;
            asset_path.push(current_asset.clone());
            hop_amounts.push(current_amount);
        }

        Ok(AmmRouteSimulation {
            asset_path,
            hop_amounts,
            amount_out: current_amount,
            hop_views,
            updated_pools: virtual_pools,
        })
    }

    fn verify_oracle_price_feed(&self, feed: &OraclePriceFeed) -> DefiResult<()> {
        self.require_asset(&feed.base_asset_id)?;
        self.require_asset(&feed.quote_asset_id)?;
        if feed.feed_id != self.oracle_feed_id(&feed.base_asset_id, &feed.quote_asset_id) {
            return Err("oracle feed id mismatch".to_string());
        }
        if feed.base_asset_id == feed.quote_asset_id {
            return Err("oracle price requires two distinct assets".to_string());
        }
        if feed.price_numerator == 0 || feed.price_denominator == 0 {
            return Err("oracle price must be positive".to_string());
        }
        if feed.confidence_bps > 10_000 {
            return Err("confidence_bps must be between 0 and 10000".to_string());
        }
        if feed.round_id == 0 {
            return Err("oracle round id must be positive".to_string());
        }
        if feed.attestations.is_empty() {
            return Err("oracle price requires attestations".to_string());
        }
        for attestation in &feed.attestations {
            if !verify_authorization(
                &attestation.publisher_label,
                "oracle_price_attestation",
                &feed.unsigned_record(),
                &attestation.authorization,
            ) {
                return Err("invalid oracle price attestation".to_string());
            }
        }
        Ok(())
    }

    fn market_oracle_feed(&self, market: &LendingMarket) -> DefiResult<Option<&OraclePriceFeed>> {
        if market.oracle_feed_id.is_empty() {
            return Ok(None);
        }
        let feed = self
            .oracle_prices
            .get(&market.oracle_feed_id)
            .ok_or_else(|| "lending market oracle price is missing".to_string())?;
        if feed.base_asset_id != market.collateral_asset_id {
            return Err("lending oracle collateral asset mismatch".to_string());
        }
        if feed.quote_asset_id != market.debt_asset_id {
            return Err("lending oracle debt asset mismatch".to_string());
        }
        Ok(Some(feed))
    }

    fn lending_collateral_value(
        &self,
        market: &LendingMarket,
        collateral_amount: u64,
    ) -> DefiResult<u64> {
        let Some(feed) = self.market_oracle_feed(market)? else {
            return Ok(collateral_amount);
        };
        let value = (collateral_amount as u128)
            .checked_mul(feed.price_numerator as u128)
            .ok_or_else(|| "lending collateral value overflow".to_string())?
            / (feed.price_denominator as u128);
        u64::try_from(value).map_err(|_| "lending collateral value overflow".to_string())
    }

    fn lending_max_borrow(
        &self,
        market: &LendingMarket,
        collateral_amount: u64,
    ) -> DefiResult<u64> {
        let collateral_value = self.lending_collateral_value(market, collateral_amount)?;
        let max_borrow =
            (collateral_value as u128) * (market.collateral_factor_bps as u128) / 10_000;
        u64::try_from(max_borrow).map_err(|_| "lending max borrow overflow".to_string())
    }

    fn lending_liquidation_limit(
        &self,
        market: &LendingMarket,
        collateral_amount: u64,
    ) -> DefiResult<(u64, u64)> {
        let collateral_value = self.lending_collateral_value(market, collateral_amount)?;
        let liquidation_limit =
            (collateral_value as u128) * (market.liquidation_threshold_bps as u128) / 10_000;
        Ok((
            collateral_value,
            u64::try_from(liquidation_limit)
                .map_err(|_| "lending liquidation limit overflow".to_string())?,
        ))
    }

    fn bump_lending_market_totals(
        &mut self,
        market_id: &str,
        collateral_delta: i128,
        debt_delta: i128,
    ) -> DefiResult<()> {
        let market = self
            .lending_markets
            .get_mut(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?;
        market.total_collateral = checked_apply_delta(
            market.total_collateral,
            collateral_delta,
            "lending market collateral total underflow",
        )?;
        market.total_debt = checked_apply_delta(
            market.total_debt,
            debt_delta,
            "lending market debt total underflow",
        )?;
        Ok(())
    }

    fn close_lending_position(&mut self, position_id: &str, status: &str) -> DefiResult<()> {
        let position = self
            .lending_positions
            .get_mut(position_id)
            .ok_or_else(|| "unknown lending position".to_string())?;
        position.status = status.to_string();
        position.closed_at_height = self.height;
        Ok(())
    }

    fn update_asset_supply(
        &mut self,
        asset_id: &str,
        minted_delta: u64,
        burned_delta: u64,
    ) -> DefiResult<()> {
        let supply = self
            .asset_supplies
            .entry(asset_id.to_string())
            .or_insert_with(|| AssetSupply::new(asset_id));
        supply.minted_amount += minted_delta;
        supply.burned_amount += burned_delta;
        Ok(())
    }

    fn enforce_asset_mint_cap(&self, asset: &Asset, amount: u64) -> DefiResult<()> {
        if asset.max_supply == 0 {
            return Ok(());
        }
        let minted = self
            .asset_supplies
            .get(&asset.asset_id)
            .map(|supply| supply.minted_amount)
            .unwrap_or(0);
        if minted + amount > asset.max_supply {
            return Err("asset mint exceeds max supply".to_string());
        }
        Ok(())
    }

    fn check_nullifier_available(&self, nullifier: &str) -> DefiResult<()> {
        if self.spent_nullifiers.iter().any(|spent| spent == nullifier) {
            return Err("duplicate nullifier".to_string());
        }
        Ok(())
    }

    fn remove_staged_note(&mut self, note_id: &str, nullifier: &str) -> DefiResult<Note> {
        let note = self.require_note(note_id)?.clone();
        if note_nullifier(&note) != nullifier {
            return Err("staged transaction nullifier mismatch".to_string());
        }
        self.check_nullifier_available(nullifier)?;
        self.notes
            .remove(note_id)
            .ok_or_else(|| "unknown or already spent staged note".to_string())
    }

    fn insert_staged_output_notes(&mut self, notes: &[Note]) -> DefiResult<()> {
        let note_ids = notes
            .iter()
            .map(|note| note.note_id.clone())
            .collect::<Vec<_>>();
        ensure_distinct(
            &note_ids,
            "staged transaction output notes must be distinct",
        )?;
        for note in notes {
            if self.notes.contains_key(&note.note_id) {
                return Err("staged transaction output note already exists".to_string());
            }
        }
        for note in notes {
            self.notes.insert(note.note_id.clone(), note.clone());
        }
        Ok(())
    }

    fn add_fee(&mut self, asset_id: &str, amount: u64) {
        *self.fees_collected.entry(asset_id.to_string()).or_insert(0) += amount;
    }
}

pub fn note_nullifier(note: &Note) -> String {
    domain_hash(
        "NULLIFIER",
        &[
            HashPart::Str(&note.note_id),
            HashPart::Str(&note.owner_view_key),
        ],
        32,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AmmRouteSimulation {
    asset_path: Vec<String>,
    hop_amounts: Vec<u64>,
    amount_out: u64,
    hop_views: Vec<Value>,
    updated_pools: BTreeMap<String, AmmPool>,
}

fn route_root_for(pool_ids: &[String], asset_path: &[String], hop_amounts: &[u64]) -> String {
    let leaves = pool_ids
        .iter()
        .zip(asset_path.windows(2))
        .zip(hop_amounts.iter())
        .map(|((pool_id, assets), amount_out)| {
            json!({
                "pool_id": pool_id,
                "asset_in_id": assets[0],
                "asset_out_id": assets[1],
                "amount_out": amount_out,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("AMM-ROUTE-HOP", &leaves)
}

pub fn oracle_feed_id(base_asset_id: &str, quote_asset_id: &str) -> String {
    domain_hash(
        "ORACLE-FEED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
        ],
        32,
    )
}

pub fn lending_owner_commitment(owner_view_key: &str) -> String {
    domain_hash("LENDING-OWNER", &[HashPart::Str(owner_view_key)], 32)
}

pub fn dark_pool_asset_pair_commitment(asset_a_id: &str, asset_b_id: &str) -> String {
    domain_hash(
        "DARK-POOL-ASSET-PAIR",
        &[HashPart::Str(asset_a_id), HashPart::Str(asset_b_id)],
        32,
    )
}

pub fn dark_pool_recipient_a_commitment(recipient_view_key: &str) -> String {
    domain_hash(
        "DARK-POOL-RECIPIENT-A",
        &[HashPart::Str(recipient_view_key)],
        32,
    )
}

pub fn dark_pool_recipient_b_commitment(recipient_view_key: &str) -> String {
    domain_hash(
        "DARK-POOL-RECIPIENT-B",
        &[HashPart::Str(recipient_view_key)],
        32,
    )
}

pub fn sealed_swap_recipient_commitment(recipient_view_key: &str) -> String {
    domain_hash(
        "SEALED-SWAP-RECIPIENT",
        &[HashPart::Str(recipient_view_key)],
        32,
    )
}

pub fn sealed_swap_owner_commitment(signer_label: &str) -> String {
    domain_hash("SEALED-SWAP-COMMITTER", &[HashPart::Str(signer_label)], 32)
}

pub fn sealed_swap_solver_commitment(solver_label: &str) -> String {
    domain_hash("SEALED-SWAP-SOLVER", &[HashPart::Str(solver_label)], 32)
}

#[allow(clippy::too_many_arguments)]
pub fn sealed_swap_order_commitment_hash(
    pool_id: &str,
    spent_note_id: &str,
    nullifier: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    amount_in: u64,
    min_amount_out: u64,
    recipient_view_key: &str,
    network_fee: u64,
    reveal_secret: &str,
) -> DefiResult<String> {
    if reveal_secret.is_empty() {
        return Err("sealed swap reveal secret is required".to_string());
    }
    Ok(domain_hash(
        "SEALED-SWAP-ORDER-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(spent_note_id),
            HashPart::Str(nullifier),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(amount_in as i128),
            HashPart::Int(min_amount_out as i128),
            HashPart::Str(&sealed_swap_recipient_commitment(recipient_view_key)),
            HashPart::Int(network_fee as i128),
            HashPart::Str(reveal_secret),
        ],
        32,
    ))
}

pub fn sealed_swap_order_commitment_id(
    pool_id: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    owner_commitment: &str,
    order_commitment: &str,
    min_reveal_height: u64,
    expires_height: u64,
) -> String {
    domain_hash(
        "SEALED-SWAP-ORDER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(order_commitment),
            HashPart::Int(min_reveal_height as i128),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

pub fn sealed_swap_batch_commitment_root(commitment_ids: &[String]) -> String {
    let leaves = commitment_ids
        .iter()
        .map(|commitment_id| Value::String(commitment_id.clone()))
        .collect::<Vec<_>>();
    merkle_root("SEALED-SWAP-COMMITMENT-ID", &leaves)
}

#[allow(clippy::too_many_arguments)]
pub fn sealed_swap_solver_bid_id(
    pool_id: &str,
    solver_label: &str,
    batch_commitment_root: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    total_amount_in: u64,
    quoted_amount_out: u64,
    network_fee_total: u64,
    expires_height: u64,
) -> String {
    domain_hash(
        "SEALED-SWAP-SOLVER-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(solver_label),
            HashPart::Str(batch_commitment_root),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(total_amount_in as i128),
            HashPart::Int(quoted_amount_out as i128),
            HashPart::Int(network_fee_total as i128),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

pub fn sealed_swap_pool_view_root(
    pool_id: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    reserve_in: u64,
    reserve_out: u64,
    fee_bps: u64,
    curve: &str,
) -> String {
    domain_hash(
        "SEALED-SWAP-POOL-VIEW",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(reserve_in as i128),
            HashPart::Int(reserve_out as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Str(curve),
        ],
        32,
    )
}

pub fn sealed_swap_route_commitment(
    pool_id: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    pool_before_root: &str,
    pool_after_root: &str,
) -> String {
    domain_hash(
        "SEALED-SWAP-ROUTE",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Str(pool_before_root),
            HashPart::Str(pool_after_root),
        ],
        32,
    )
}

pub fn sealed_swap_minimum_output_commitment(min_amount_out: u64) -> String {
    domain_hash(
        "SEALED-SWAP-MINIMUM-OUTPUT",
        &[HashPart::Int(min_amount_out as i128)],
        32,
    )
}

pub fn sealed_swap_surplus_commitment(surplus: u64) -> String {
    domain_hash("SEALED-SWAP-SURPLUS", &[HashPart::Int(surplus as i128)], 32)
}

#[allow(clippy::too_many_arguments)]
pub fn sealed_swap_clearing_price_commitment_root(
    pool_id: &str,
    route_commitment: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    total_amount_in: u64,
    total_amount_out: u64,
    clearing_price_numerator: u64,
    clearing_price_denominator: u64,
    pool_curve: &str,
) -> String {
    domain_hash(
        "SEALED-SWAP-CLEARING-PRICE-COMMITMENT",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(route_commitment),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(total_amount_in as i128),
            HashPart::Int(total_amount_out as i128),
            HashPart::Int(clearing_price_numerator as i128),
            HashPart::Int(clearing_price_denominator as i128),
            HashPart::Str(pool_curve),
        ],
        32,
    )
}

pub fn sealed_swap_aggregate_surplus_commitment_root(
    intent_count: u64,
    intent_root: &str,
    surplus_commitment_root: &str,
    total_surplus_amount: u64,
) -> String {
    domain_hash(
        "SEALED-SWAP-AGGREGATE-SURPLUS-COMMITMENT",
        &[
            HashPart::Int(intent_count as i128),
            HashPart::Str(intent_root),
            HashPart::Str(surplus_commitment_root),
            HashPart::Int(total_surplus_amount as i128),
        ],
        32,
    )
}

pub fn sealed_swap_settlement_receipt_id(
    block_height: u64,
    tx_public_hash: &str,
    intent_root: &str,
    solver_label: &str,
) -> String {
    domain_hash(
        "SEALED-SWAP-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Str(tx_public_hash),
            HashPart::Str(intent_root),
            HashPart::Str(solver_label),
        ],
        32,
    )
}

pub fn sealed_swap_tx_public_hash(tx: &AmmSealedBatchSwap) -> String {
    domain_hash("TX-PUBLIC", &[HashPart::Json(&tx.public_record())], 32)
}

fn sealed_swap_output_asset(pool: &AmmPool, asset_in_id: &str) -> DefiResult<String> {
    if asset_in_id == pool.asset_a_id {
        return Ok(pool.asset_b_id.clone());
    }
    if asset_in_id == pool.asset_b_id {
        return Ok(pool.asset_a_id.clone());
    }
    Err("sealed swap note does not match pool assets".to_string())
}

fn sealed_swap_receipt_roots(tx: &AmmSealedBatchSwap) -> DefiResult<(String, String, String, u64)> {
    let mut fill_items = Vec::with_capacity(tx.fills.len());
    let mut minimum_items = Vec::with_capacity(tx.fills.len());
    let mut surplus_items = Vec::with_capacity(tx.fills.len());
    let mut total_surplus = 0_u64;
    for fill in &tx.fills {
        if fill.amount_out < fill.intent.min_amount_out {
            return Err("sealed swap settlement receipt below minimum".to_string());
        }
        let intent_hash = fill.intent.intent_hash();
        let surplus = fill.amount_out - fill.intent.min_amount_out;
        total_surplus = total_surplus
            .checked_add(surplus)
            .ok_or_else(|| "sealed swap surplus overflow".to_string())?;
        fill_items.push(json!({
            "intent_hash": intent_hash.clone(),
            "output_commitment": fill.output_note.commitment,
            "change_commitment": fill.change_note.as_ref().map(|note| note.commitment.clone()).unwrap_or_default(),
        }));
        minimum_items.push(json!({
            "intent_hash": intent_hash.clone(),
            "minimum_output_commitment": sealed_swap_minimum_output_commitment(fill.intent.min_amount_out),
        }));
        surplus_items.push(json!({
            "intent_hash": intent_hash,
            "surplus_commitment": sealed_swap_surplus_commitment(surplus),
        }));
    }
    Ok((
        merkle_root("SEALED-SWAP-FILL-COMMITMENT", &fill_items),
        merkle_root("SEALED-SWAP-MINIMUM-OUTPUT", &minimum_items),
        merkle_root("SEALED-SWAP-SURPLUS", &surplus_items),
        total_surplus,
    ))
}

pub fn lending_liquidator_commitment(liquidator_view_key: &str) -> String {
    domain_hash(
        "LENDING-LIQUIDATOR",
        &[HashPart::Str(liquidator_view_key)],
        32,
    )
}

pub fn lending_borrow_terms_hash(
    market_id: &str,
    collateral_amount: u64,
    borrow_amount: u64,
    borrow_fee: u64,
) -> String {
    domain_hash(
        "LENDING-BORROW-TERMS",
        &[
            HashPart::Str(market_id),
            HashPart::Int(collateral_amount as i128),
            HashPart::Int(borrow_amount as i128),
            HashPart::Int(borrow_fee as i128),
        ],
        32,
    )
}

pub fn lending_repay_terms_hash(
    position_id: &str,
    repay_fee: u64,
    output_notes: &[Note],
) -> String {
    let commitments = output_commitments(output_notes);
    domain_hash(
        "LENDING-REPAY-TERMS",
        &[
            HashPart::Str(position_id),
            HashPart::Int(repay_fee as i128),
            HashPart::Json(&commitments),
        ],
        32,
    )
}

pub fn lending_liquidation_terms_hash(
    position_id: &str,
    liquidation_fee: u64,
    liquidator_commitment: &str,
    output_notes: &[Note],
) -> String {
    let commitments = output_commitments(output_notes);
    domain_hash(
        "LENDING-LIQUIDATION-TERMS",
        &[
            HashPart::Str(position_id),
            HashPart::Int(liquidation_fee as i128),
            HashPart::Str(liquidator_commitment),
            HashPart::Json(&commitments),
        ],
        32,
    )
}

fn output_commitments(output_notes: &[Note]) -> Value {
    Value::Array(
        output_notes
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect(),
    )
}

fn note_totals_by_asset(notes: &[Note]) -> DefiResult<BTreeMap<String, u64>> {
    let mut totals = BTreeMap::<String, u64>::new();
    for note in notes {
        let total = totals.entry(note.asset_id.clone()).or_insert(0);
        *total = total
            .checked_add(note.amount)
            .ok_or_else(|| "note total overflow".to_string())?;
    }
    Ok(totals)
}

fn ensure_distinct(values: &[String], message: &str) -> DefiResult<()> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() == values.len() {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn checked_apply_delta(current: u64, delta: i128, underflow_message: &str) -> DefiResult<u64> {
    if delta.is_negative() {
        current
            .checked_sub(delta.unsigned_abs() as u64)
            .ok_or_else(|| underflow_message.to_string())
    } else {
        current
            .checked_add(delta as u64)
            .ok_or_else(|| "lending market total overflow".to_string())
    }
}

pub fn validate_amm_curve(curve: &str) -> DefiResult<String> {
    let normalized = curve.trim().to_ascii_lowercase().replace('-', "_");
    if matches!(normalized.as_str(), "constant_product" | "stable") {
        Ok(normalized)
    } else {
        Err("unsupported AMM curve".to_string())
    }
}

pub fn amm_asset_view(pool: &AmmPool, asset_in_id: &str) -> DefiResult<(u64, u64, String)> {
    if asset_in_id == pool.asset_a_id {
        return Ok((pool.reserve_a, pool.reserve_b, pool.asset_b_id.clone()));
    }
    if asset_in_id == pool.asset_b_id {
        return Ok((pool.reserve_b, pool.reserve_a, pool.asset_a_id.clone()));
    }
    Err("swap note does not match pool assets".to_string())
}

pub fn amm_output_amount(
    pool: &AmmPool,
    reserve_in: u64,
    reserve_out: u64,
    amount_in: u64,
) -> DefiResult<u64> {
    let effective_in = (amount_in as u128) * (10_000 - pool.fee_bps) as u128 / 10_000;
    if pool.curve == "stable" {
        return Ok(std::cmp::min(effective_in as u64, reserve_out));
    }
    if reserve_in == 0 {
        return Err("pool has no liquidity".to_string());
    }
    Ok(((reserve_out as u128) * effective_in / ((reserve_in as u128) + effective_in)) as u64)
}

pub fn updated_pool_for_swap(
    pool: &AmmPool,
    asset_in_id: &str,
    amount_in: u64,
    amount_out: u64,
) -> DefiResult<AmmPool> {
    if asset_in_id == pool.asset_a_id {
        if amount_out > pool.reserve_b {
            return Err("AMM swap would make a negative reserve".to_string());
        }
        return Ok(AmmPool {
            reserve_a: pool.reserve_a + amount_in,
            reserve_b: pool.reserve_b - amount_out,
            ..pool.clone()
        });
    }
    if asset_in_id == pool.asset_b_id {
        if amount_out > pool.reserve_a {
            return Err("AMM swap would make a negative reserve".to_string());
        }
        return Ok(AmmPool {
            reserve_a: pool.reserve_a - amount_out,
            reserve_b: pool.reserve_b + amount_in,
            ..pool.clone()
        });
    }
    Err("swap note does not match pool assets".to_string())
}

pub fn amm_lp_minted(pool: &AmmPool, amount_a: u64, amount_b: u64) -> DefiResult<u64> {
    if pool.total_lp == 0 {
        if pool.curve == "stable" {
            return Ok(amount_a + amount_b);
        }
        return Ok(integer_sqrt((amount_a as u128) * (amount_b as u128)));
    }
    if pool.reserve_a == 0 || pool.reserve_b == 0 {
        return Err("pool has inconsistent liquidity".to_string());
    }
    Ok(std::cmp::min(
        ((amount_a as u128) * (pool.total_lp as u128) / (pool.reserve_a as u128)) as u64,
        ((amount_b as u128) * (pool.total_lp as u128) / (pool.reserve_b as u128)) as u64,
    ))
}

fn integer_sqrt(value: u128) -> u64 {
    if value < 2 {
        return value as u64;
    }
    let mut x = value;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    x as u64
}

fn asset_issuer_label(asset: &Asset) -> String {
    asset
        .issuer_policy
        .split_once(':')
        .map(|(_, label)| label.to_string())
        .unwrap_or_else(|| asset.issuer_policy.clone())
}

fn asset_supports_native_mint_burn(asset: &Asset) -> bool {
    matches!(asset.supply_policy.as_str(), "mint-burn" | "fixed")
        && !asset.issuer_policy.starts_with("bridge:")
        && !asset.issuer_policy.starts_with("amm:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_note_and_roots_match_python_reference_vectors() {
        let mut state = DefiState::new();
        let asset = state
            .create_asset(
                "WXMR",
                "devnet-bridge-threshold",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let note = state
            .mint(&asset.asset_id, "alice-view-key", 1_000)
            .unwrap();

        assert_eq!(
            asset.asset_id,
            "b06b2e54ae741782ab93575dbf06922ea95ed343a68cd6d6eb3611e442b9b347"
        );
        assert_eq!(
            note.note_id,
            "b70be52d3de53ecee2adb9d235b8d317148fda7625130d08c1583a98561cc558"
        );
        assert_eq!(
            note.commitment,
            "f67a59259cf6b916dd9ea2c92b4d62d77dc4f86b0cf97229428656ba66f34f9a"
        );
        assert_eq!(
            state.asset_root(),
            "62cb7ed32dd066d9843c6180f62f6444945cd5af22e22ba7db663dd8008ecc60"
        );
        assert_eq!(
            state.note_root(),
            "83cf847669bf2ce1afaf2a2a34544167031460db98a5045dd6553ba5a8fadeed"
        );
    }

    #[test]
    fn native_asset_mint_and_private_burn_updates_supply_without_public_owner_leak() {
        let mut state = DefiState::new();
        let asset = state
            .create_native_asset("DGR", "issuer:treasury-key", 1_500)
            .unwrap();

        assert!(state
            .submit_asset_mint(
                &asset.asset_id,
                "alice-view-key",
                1_000,
                Some("mallory-key")
            )
            .is_err());

        let mint = state
            .submit_asset_mint(&asset.asset_id, "alice-view-key", 1_000, None)
            .unwrap();
        let public_mint = mint.public_record();
        assert_eq!(public_mint["kind"], "asset_mint");
        assert_eq!(public_mint["amount"], 1_000);
        assert!(!public_mint.to_string().contains("alice-view-key"));
        assert!(public_mint["auth_signature"].as_str().unwrap().len() > 100);
        assert_eq!(
            state
                .asset_supplies
                .get(&asset.asset_id)
                .unwrap()
                .minted_amount,
            1_000
        );

        let burn = state
            .submit_asset_burn(&mint.output_note.note_id, 400, None)
            .unwrap();
        let public_burn = burn.public_record();
        assert_eq!(public_burn["kind"], "asset_burn");
        assert_eq!(public_burn["amount"], 400);
        assert!(public_burn.get("spent_note_id").is_none());
        assert!(!public_burn.to_string().contains("alice-view-key"));
        assert!(
            public_burn["proof_bundle"]["proof_root"]
                .as_str()
                .unwrap()
                .len()
                == 64
        );

        let supply = state.asset_supplies.get(&asset.asset_id).unwrap();
        assert_eq!(supply.minted_amount, 1_000);
        assert_eq!(supply.burned_amount, 400);
        assert_eq!(supply.circulating_amount(), 600);
        let wallet = state.wallet_notes("alice-view-key");
        assert_eq!(wallet.len(), 1);
        assert_eq!(wallet[0]["amount"], 600);
    }

    #[test]
    fn amm_liquidity_and_swaps_match_python_reference_amounts() {
        let mut state = DefiState::new();
        let wxmr = state
            .create_asset(
                "WXMR",
                "devnet-bridge-threshold",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let dusd = state
            .create_asset(
                "DUSD",
                "devnet-stable-issuer",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let xmr_note = state.mint(&wxmr.asset_id, "lp-view-key", 10_000).unwrap();
        let usd_note = state.mint(&dusd.asset_id, "lp-view-key", 20_000).unwrap();
        let pool = state
            .create_amm_pool(&wxmr.asset_id, &dusd.asset_id, 30, "constant-product")
            .unwrap();
        let liquidity = state
            .submit_amm_liquidity_add(
                &pool.pool_id,
                &xmr_note.note_id,
                &usd_note.note_id,
                5_000,
                10_000,
                "lp-view-key",
                5,
                None,
            )
            .unwrap();
        assert_eq!(liquidity.lp_minted, 7_071);
        assert!(
            liquidity.public_record()["proof_bundle"]["proof_root"]
                .as_str()
                .unwrap()
                .len()
                == 64
        );

        let trader_note = state
            .mint(&wxmr.asset_id, "trader-view-key", 1_500)
            .unwrap();
        let swap = state
            .submit_amm_swap(
                &pool.pool_id,
                &trader_note.note_id,
                1_000,
                1_600,
                "trader-view-key",
                2,
                None,
            )
            .unwrap();
        assert_eq!(swap.amount_out, 1_662);
        let updated = state.pools.get(&pool.pool_id).unwrap();
        assert_eq!(updated.reserve_a, 6_000);
        assert_eq!(updated.reserve_b, 8_338);
        assert_eq!(state.fees_collected.get(&wxmr.asset_id), Some(&7));
        assert_eq!(state.amm_pool_root().len(), 64);

        let dusc = state
            .create_asset(
                "DUSC",
                "devnet-stable-issuer",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let stable_a = state
            .mint(&dusd.asset_id, "stable-lp-view-key", 20_000)
            .unwrap();
        let stable_b = state
            .mint(&dusc.asset_id, "stable-lp-view-key", 20_000)
            .unwrap();
        let stable_pool = state
            .create_amm_pool(&dusd.asset_id, &dusc.asset_id, 5, "stable")
            .unwrap();
        let stable_liquidity = state
            .submit_amm_liquidity_add(
                &stable_pool.pool_id,
                &stable_a.note_id,
                &stable_b.note_id,
                10_000,
                10_000,
                "stable-lp-view-key",
                5,
                None,
            )
            .unwrap();
        assert_eq!(stable_liquidity.lp_minted, 20_000);
        let stable_trader = state
            .mint(&dusd.asset_id, "stable-trader-view-key", 1_500)
            .unwrap();
        let stable_swap = state
            .submit_amm_swap(
                &stable_pool.pool_id,
                &stable_trader.note_id,
                1_000,
                995,
                "stable-trader-view-key",
                2,
                None,
            )
            .unwrap();
        assert_eq!(stable_swap.amount_out, 999);
        let stable_updated = state.pools.get(&stable_pool.pool_id).unwrap();
        assert_eq!(stable_updated.reserve_a, 11_000);
        assert_eq!(stable_updated.reserve_b, 9_001);
    }

    #[test]
    fn private_lending_borrow_and_repay_hide_position_owner() {
        let mut state = DefiState::new();
        let wxmr = state
            .create_asset(
                "WXMR",
                "devnet-bridge-threshold",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let dusd = state
            .create_asset(
                "DUSD",
                "devnet-stable-issuer",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let feed = state
            .publish_oracle_price(&wxmr.asset_id, &dusd.asset_id, 2, 1, 50, &["oracle-a"])
            .unwrap();
        let market = state
            .create_lending_market(
                &wxmr.asset_id,
                &dusd.asset_id,
                5_000,
                7_500,
                Some(&feed.feed_id),
            )
            .unwrap();
        let collateral_note = state.mint(&wxmr.asset_id, "alice-view-key", 1_000).unwrap();
        state.set_height(3);
        let borrow = state
            .submit_lending_borrow(
                &market.market_id,
                &collateral_note.note_id,
                600,
                500,
                "alice-view-key",
                5,
                None,
            )
            .unwrap();

        let public_borrow = borrow.public_record();
        assert_eq!(public_borrow["kind"], "lending_borrow");
        assert!(public_borrow.get("spent_collateral_note_id").is_none());
        assert!(!public_borrow.to_string().contains("alice-view-key"));
        assert!(
            public_borrow["proof_bundle"]["proof_root"]
                .as_str()
                .unwrap()
                .len()
                == 64
        );
        let position = state.lending_positions.get(&borrow.position_id).unwrap();
        assert_eq!(position.status, "active");
        assert_eq!(position.created_at_height, 3);
        assert_eq!(
            position.public_record()["owner_commitment"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert!(!position
            .public_record()
            .to_string()
            .contains("alice-view-key"));
        assert_eq!(state.lending_market_root().len(), 64);
        assert_eq!(state.lending_position_root().len(), 64);

        let debt_note = borrow.output_notes[0].clone();
        state.set_height(8);
        let repay = state
            .submit_lending_repay(&borrow.position_id, &debt_note.note_id, 0, None)
            .unwrap();
        let public_repay = repay.public_record();
        assert_eq!(public_repay["kind"], "lending_repay");
        assert!(public_repay.get("spent_debt_note_id").is_none());
        assert!(!public_repay.to_string().contains("alice-view-key"));
        let repaid = state.lending_positions.get(&borrow.position_id).unwrap();
        assert_eq!(repaid.status, "repaid");
        assert_eq!(repaid.closed_at_height, 8);
        let updated_market = state.lending_markets.get(&market.market_id).unwrap();
        assert_eq!(updated_market.total_collateral, 0);
        assert_eq!(updated_market.total_debt, 0);
        assert_eq!(state.fees_collected.get(&wxmr.asset_id), Some(&5));
    }

    #[test]
    fn oracle_backed_lending_liquidation_uses_public_price_root() {
        let mut state = DefiState::new();
        let wxmr = state
            .create_asset(
                "WXMR",
                "devnet-bridge-threshold",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let dusd = state
            .create_asset(
                "DUSD",
                "devnet-stable-issuer",
                "mint-burn",
                "shielded",
                0,
                &json!({}),
            )
            .unwrap();
        let feed = state
            .publish_oracle_price(
                &wxmr.asset_id,
                &dusd.asset_id,
                2,
                1,
                25,
                &["oracle-a", "oracle-b"],
            )
            .unwrap();
        let market = state
            .create_lending_market(
                &wxmr.asset_id,
                &dusd.asset_id,
                5_000,
                7_500,
                Some(&feed.feed_id),
            )
            .unwrap();
        let collateral_note = state
            .mint(&wxmr.asset_id, "borrower-view-key", 1_000)
            .unwrap();
        let borrow = state
            .submit_lending_borrow(
                &market.market_id,
                &collateral_note.note_id,
                500,
                500,
                "borrower-view-key",
                0,
                None,
            )
            .unwrap();
        let liquidator_debt = state.mint(&dusd.asset_id, "liquidator-funds", 503).unwrap();

        assert_eq!(
            state.submit_lending_liquidation(
                &borrow.position_id,
                &liquidator_debt.note_id,
                "liquidator-view-key",
                3,
                None,
            ),
            Err("lending position is not liquidatable".to_string())
        );

        state
            .publish_oracle_price(&wxmr.asset_id, &dusd.asset_id, 1, 2, 25, &["oracle-a"])
            .unwrap();
        let liquidation = state
            .submit_lending_liquidation(
                &borrow.position_id,
                &liquidator_debt.note_id,
                "liquidator-view-key",
                3,
                None,
            )
            .unwrap();
        let public_liquidation = liquidation.public_record();
        assert_eq!(public_liquidation["kind"], "lending_liquidation");
        assert!(public_liquidation.get("spent_debt_note_id").is_none());
        assert!(public_liquidation.get("liquidator_view_key").is_none());
        assert_eq!(
            public_liquidation["liquidator_commitment"],
            Value::String(lending_liquidator_commitment("liquidator-view-key"))
        );
        assert!(!public_liquidation
            .to_string()
            .contains("liquidator-view-key"));
        assert_eq!(
            state.lending_positions[&borrow.position_id].status,
            "liquidated"
        );
        assert_eq!(state.lending_markets[&market.market_id].total_collateral, 0);
        assert_eq!(state.lending_markets[&market.market_id].total_debt, 0);
        assert_eq!(state.oracle_root().len(), 64);
        assert_eq!(state.lending_root().len(), 64);
    }
}
